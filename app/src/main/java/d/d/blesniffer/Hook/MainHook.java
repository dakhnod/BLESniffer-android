package d.d.blesniffer.Hook;

import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothSocket;
import android.util.Log;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import static de.robv.android.xposed.XposedHelpers.findAndHookConstructor;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;

public class MainHook implements IXposedHookLoadPackage {
    HashMap<String, BluetoothGatt> gattServers = new HashMap<>();
    String logIdentifier = "";

    @Override
    public void handleLoadPackage(final XC_LoadPackage.LoadPackageParam pck) throws Throwable {
        this.logIdentifier = pck.packageName;

        log("hooking");

        hookBLENotify(pck);
        hookBLEWrite();

        hookFossil(pck);

        hookCrypto();

        log("hooked");
    }

    private void hookCrypto() {
        findAndHookMethod(Cipher.class, "init", int.class, Key.class, AlgorithmParameterSpec.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                Key key = (Key) param.args[1];
                AlgorithmParameterSpec spec = (AlgorithmParameterSpec) param.args[2];
                if(spec instanceof IvParameterSpec){
                    IvParameterSpec iv = (IvParameterSpec) spec;
                    log("key: " + bytesToHex(key.getEncoded()) + "   iv: " + bytesToHex(iv.getIV()));
                }
            }
        });
    }

    private void hookFossil(final XC_LoadPackage.LoadPackageParam pck){
        if(pck.packageName.equals("com.fossil.wearables.fossil")){
            findAndHookMethod("com.fossil.crypto.EllipticCurveKeyPair$CppProxy", pck.classLoader, "create", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);

                    log("KeyPair create() called");

                    Method method = param.getResult().getClass().getDeclaredMethod("publicKey");
                    method.setAccessible(true);
                    byte[] publicKey = (byte[]) method.invoke(param.getResult());

                    method = param.getResult().getClass().getDeclaredMethod("privateKey");
                    method.setAccessible(true);
                    byte[] privateKey = (byte[]) method.invoke(param.getResult());

                    log("public key: " + bytesToHex(publicKey));
                    log("privateKey key: " + bytesToHex(privateKey));
                }
            });

            findAndHookConstructor(SecretKeySpec.class, byte[].class, String.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    String alg = (String) param.args[1];
                    byte[] key = (byte[]) param.args[0];

                    if(!alg.equals("AES") || key.length != 16) return;
                    log("SecretKeySpec(): " + param.args[1] + "   " + bytesToHex((byte[]) param.args[0]));
                }
            });
        }
    }

    private BluetoothGatt getDeviceGatt(String address){
        return gattServers.get(address);
    }

    private BluetoothGattCharacteristic getCharacteristicById(BluetoothGatt gatt, int id){
        List<BluetoothGattService> services = gatt.getServices();
        for(BluetoothGattService service : services){
            List<BluetoothGattCharacteristic> characteristics = service.getCharacteristics();
            for(BluetoothGattCharacteristic characteristic : characteristics){
                if(characteristic.getInstanceId() == id) return characteristic;
            }
        }

        return null;
    }

    private void hookBLENotify(final XC_LoadPackage.LoadPackageParam pck){
        findAndHookMethod("android.bluetooth.BluetoothGatt$1", pck.classLoader, "onNotify", String.class, int.class, byte[].class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);

                String deviceAddress = (String) param.args[0];
                int instanceId = (int) param.args[1];
                byte[] value = (byte[]) param.args[2];
                BluetoothGatt gatt = getDeviceGatt(deviceAddress);

                if(gatt == null) {
                    log("gatt not found");
                    return;
                };

                BluetoothGattCharacteristic characteristic = getCharacteristicById(gatt, instanceId);

                log("characteristic change " + characteristic.getUuid() + " " + bytesToHex(value));
            }
        });
    }

    private void hookBLEWrite(){
        findAndHookMethod(BluetoothGatt.class, "writeCharacteristic", BluetoothGattCharacteristic.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);

                BluetoothGattCharacteristic characteristic = (BluetoothGattCharacteristic) param.args[0];
                BluetoothGatt gatt = (BluetoothGatt) param.thisObject;

                if(!gattServers.containsKey(gatt.getDevice().getAddress())){
                    gattServers.put(gatt.getDevice().getAddress(), gatt);
                }

                log("characteristic write " + characteristic.getUuid() + " " + bytesToHex(characteristic.getValue()));
            }
        });

        findAndHookMethod(BluetoothGatt.class, "writeDescriptor", BluetoothGattDescriptor.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);

                BluetoothGattDescriptor descriptor = (BluetoothGattDescriptor) param.args[0];
                BluetoothGatt gatt = (BluetoothGatt) param.thisObject;

                if(!gattServers.containsKey(gatt.getDevice().getAddress())){
                    gattServers.put(gatt.getDevice().getAddress(), gatt);
                }

                log("descriptor write " + descriptor.getUuid() + "  " + bytesToHex(descriptor.getValue()));
            }
        });
    }

    private String bytesToHex(byte[] bytes) {
        final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        String hex = "";
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hex += HEX_ARRAY[v >>> 4];
            hex += HEX_ARRAY[v & 0x0F];
            hex += " ";
        }
        return hex;
    }

    private void log(String data){
        Log.d("BLESniffer_" + logIdentifier, data);
    }
}
