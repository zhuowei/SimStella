package net.zhuoweizhang.simstella

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothServerSocket
import android.bluetooth.BluetoothSocket
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import com.google.protobuf.ByteString
import com.google.protobuf.kotlin.toByteString
import com.oculus.atc.EnableEncryption
import com.oculus.atc.MessageTypeSetup
import com.oculus.atc.RequestEncryption
import com.oculus.atc.enableEncryption
import com.oculus.atc.requestEncryption
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.HexFormat
import java.util.UUID
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import net.zhuoweizhang.simstella.ui.theme.SimStellaTheme

val fbGattServiceUuid = UUID.fromString("0000FD5F-0000-1000-8000-00805F9B34FB")
val fbPsmCharacteristicUuid = UUID.fromString("05ACBE9F-6F61-4CA9-80BF-C8BBB52991C0")
val firmwareGattServiceUuid = UUID.fromString("0000180A-0000-1000-8000-00805F9B34FB")
val firmwareCharacteristicUuid = UUID.fromString("00002A26-0000-1000-8000-00805F9B34FB")

class MainActivity : ComponentActivity() {
  lateinit var l2capChannel: BluetoothServerSocket
  lateinit var bluetoothGattServer: BluetoothGattServer

  override fun onCreate(savedInstanceState: Bundle?) {
    // too lazy to do the permissions thing
    // pm grant net.zhuoweizhang.simstella android.permission.BLUETOOTH_CONNECT
    // pm grant net.zhuoweizhang.simstella android.permission.BLUETOOTH_ADVERTISE
    super.onCreate(savedInstanceState)
    enableEdgeToEdge()
    setContent {
      SimStellaTheme {
        Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
          Greeting(name = "Android", modifier = Modifier.padding(innerPadding))
        }
      }
    }
    val bluetoothManager = getSystemService(BLUETOOTH_SERVICE) as BluetoothManager
    val bluetoothAdapter = bluetoothManager.adapter
    val advertisingData =
      AdvertiseData.Builder()
        .addManufacturerData(0x1ab, byteArrayOf(0x3, 0x1, 0x1))
        .setIncludeDeviceName(true)
        .build()
    val advertiseSettings = AdvertiseSettings.Builder().setConnectable(true).build()
    bluetoothAdapter.bluetoothLeAdvertiser.startAdvertising(
      advertiseSettings,
      advertisingData,
      object : AdvertiseCallback() {
        override fun onStartFailure(errorCode: Int) {
          println("advertise start failure: $errorCode")
        }

        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
          println("advertise start success")
        }
      },
    )
    bluetoothGattServer = bluetoothManager.openGattServer(this, MyCallback())
    bluetoothGattServer.addService(makeFbGattService())
    // bluetoothGattServer.addService(makeFirmwareGattService())
    l2capChannel = bluetoothAdapter.listenUsingL2capChannel()
    println("!!!!l2cap: ${l2capChannel.psm}")
    val keypairGenerator = KeyPairGenerator.getInstance("EC")
    val keyPair = keypairGenerator.generateKeyPair()
    val ecBytes = getBytesForPublicKey(keyPair.public)
    val listenThread =
      Thread() {
        while (true) {
          try {
            val sock = l2capChannel.accept()
            println("accepted a sock?!")
            handleSocket(sock, ecBytes, keyPair)
          } catch (e: Exception) {
            e.printStackTrace()
            break
          }
        }
      }
    listenThread.start()
  }

  inner class MyCallback : BluetoothGattServerCallback() {
    override fun onCharacteristicReadRequest(
      device: BluetoothDevice?,
      requestId: Int,
      offset: Int,
      characteristic: BluetoothGattCharacteristic?,
    ) {
      println("read characteristic $characteristic")
      when (characteristic!!.uuid) {
        firmwareCharacteristicUuid -> {
          val buf = "ABCD".toByteArray(StandardCharsets.UTF_16)
          bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, buf)
        }
        fbPsmCharacteristicUuid -> {
          val port = l2capChannel.psm
          val buf =
            byteArrayOf(
              0x41.toByte(),
              0x42.toByte(),
              (port and 0xff).toByte(),
              (port shr 8).toByte(),
            )
          bluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, buf)
        }
        else -> {
          println("unknown characteristic $characteristic?")
        }
      }
    }
  }

  fun handleSocket(sock: BluetoothSocket, ecBytes: ByteArray, ecKeyPair: KeyPair) {
    while (true) {
      val bytes = ByteArray(0x100)
      val lengthRead = sock.inputStream.read(bytes)
      println("read bytes: ${HexFormat.of().formatHex(bytes, 0, lengthRead)}")
      if (lengthRead > 8 && bytes[4].toInt() != 3) {
        val headerOff =
          if (bytes[4].toInt() == 2) {
            4
          } else {
            8
          }
        val protoData = ByteString.copyFrom(bytes, headerOff + 4, lengthRead - (headerOff + 4))
        val protoType = bytes[headerOff + 3].toInt()
        when (protoType) {
          MessageTypeSetup.REQUEST_ENCRYPTION_VALUE -> {
            val msg = RequestEncryption.parseFrom(protoData)
            println(msg)
            val response = requestEncryption {
              publicKey = ecBytes.toByteString()
              challenge = "0123456789abcdef".toByteArray().toByteString()
              ellipticCurve = 0
              supportedParameters = 31
            }
            val responseOut = response.toByteArray()
            val replySize = 12 + responseOut.size
            val reply = ByteArray(replySize)
            // 80608001 81000005 02000001
            val header =
              byteArrayOf(
                0x80.toByte(),
                (replySize - 4).toByte(),
                0x80.toByte(),
                0x01,
                0x81.toByte(),
                0x00,
                0x00,
                0x05,
                0x02,
                0x00,
                0x00,
                0x01,
              )
            header.copyInto(reply, 0)
            responseOut.copyInto(reply, 12)
            sock.outputStream.write(reply)
          }
          MessageTypeSetup.ENABLE_ENCRYPTION_VALUE -> {
            val msg = EnableEncryption.parseFrom(protoData)
            println(msg)
            val response = enableEncryption {
              publicKey = ecBytes.toByteString()
              seed = "A".repeat(32).toByteArray().toByteString()
              iv = "B".repeat(16).toByteArray().toByteString()
              base = 0x41424344 // this changes every time?
              // 1 << 1 is multiplexing; not sure about others
              parameters = 31
            }
            val responseOut = response.toByteArray()
            val replySize = 8 + responseOut.size
            val reply = ByteArray(replySize)
            val header =
              byteArrayOf(
                0x80.toByte(),
                (replySize - 4).toByte(),
                0x00,
                0x01,
                0x02,
                0x00,
                0x00,
                0x02,
              )
            header.copyInto(reply, 0)
            responseOut.copyInto(reply, 8)
            sock.outputStream.write(reply)
            val remotePublicKey = makeRemotePublicKey(msg.publicKey)
            val keyAgreement = KeyAgreement.getInstance("ECDH")
            keyAgreement.init(ecKeyPair.private)
            keyAgreement.doPhase(remotePublicKey, true)
            val sharedSecret = keyAgreement.generateSecret()
            println("dh: ${HexFormat.of().formatHex(sharedSecret)}")
            val hashedSharedSecret = MessageDigest.getInstance("SHA-256").digest(sharedSecret)
          }
          else -> {
            sock.outputStream.write(bytes, 0, lengthRead)
          }
        }
      }
      if (lengthRead <= 0) {
        break
      }
    }
    sock.close()
  }
}

fun makeFbGattService(): BluetoothGattService {
  val bluetoothGattService =
    BluetoothGattService(fbGattServiceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)
  bluetoothGattService.addCharacteristic(
    BluetoothGattCharacteristic(
      fbPsmCharacteristicUuid,
      BluetoothGattCharacteristic.PROPERTY_READ,
      BluetoothGattCharacteristic.PERMISSION_READ,
    )
  )
  return bluetoothGattService
}

fun makeFirmwareGattService(): BluetoothGattService {
  val bluetoothGattService =
    BluetoothGattService(firmwareGattServiceUuid, BluetoothGattService.SERVICE_TYPE_PRIMARY)
  bluetoothGattService.addCharacteristic(
    BluetoothGattCharacteristic(
      firmwareCharacteristicUuid,
      BluetoothGattCharacteristic.PROPERTY_READ,
      BluetoothGattCharacteristic.PERMISSION_READ,
    )
  )
  return bluetoothGattService
}

fun getBytesForPublicKey(key: PublicKey): ByteArray {
  val encoded = key.encoded
  // too lazy to get a real asn1 parser, hardcode the offset
  return encoded.copyOfRange(0x1b, 0x1b + 0x40)
}

val EC_ASN1_HEADER =
  byteArrayOf(
    0x30,
    0x59,
    0x30,
    0x13,
    0x06,
    0x07,
    0x2a,
    0x86.toByte(),
    0x48,
    0xce.toByte(),
    0x3d,
    0x02,
    0x01,
    0x06,
    0x08,
    0x2a,
    0x86.toByte(),
    0x48,
    0xce.toByte(),
    0x3d,
    0x03,
    0x01,
    0x07,
    0x03,
    0x42,
    0x00,
    0x04,
  )

fun makeRemotePublicKey(bytes: ByteString): PublicKey {
  val keyFactory = KeyFactory.getInstance("EC")
  // no real asn1 writer here...
  val asn1Bytes = ByteArray(0x1b + 0x40)
  EC_ASN1_HEADER.copyInto(asn1Bytes, 0)
  bytes.copyTo(asn1Bytes, 0x1b)
  val pkSpec = X509EncodedKeySpec(asn1Bytes)
  return keyFactory.generatePublic(pkSpec)
}

fun computeEncryptionKey(
  sharedSecret: ByteArray,
  challenge: ByteArray,
  seed: ByteArray,
): ByteArray {
  val md = MessageDigest.getInstance("SHA-256")
  md.update(challenge)
  val firstHmacSecret = md.digest(seed)

  val hmac = Mac.getInstance("HmacSHA256")
  hmac.init(SecretKeySpec(firstHmacSecret, "HmacSHA256"))
  hmac.update(sharedSecret)
  val hmac1 = hmac.doFinal()

  hmac.reset()

  hmac.init(SecretKeySpec(hmac1, "HmacSHA256"))
  hmac.update("AirShield".toByteArray())
  hmac.update(0x01)
  val hmac2 = hmac.doFinal()

  // TODO: also the hmac key...
  return hmac2
}

@Composable
fun Greeting(name: String, modifier: Modifier = Modifier) {
  Text(text = "Hello $name!", modifier = modifier)
}

@Preview(showBackground = true)
@Composable
fun GreetingPreview() {
  SimStellaTheme { Greeting("Android") }
}
