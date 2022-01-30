package d.d.blesniffer.Hook;

import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.util.Base64;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
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

        hookBLClassicStreams(pck);
        hookBLENotify(pck);
        hookBLEWrite();
        hookCipher();

        log("hooked");
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

    private void hookBLClassicStreams(final XC_LoadPackage.LoadPackageParam pck){
        findAndHookMethod("android.bluetooth.BluetoothOutputStream", pck.classLoader, "write", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);

                byte[] data = (byte[]) param.args[0];
                JSONObject jsonObject = new JSONObject()
                        .put("payload", bytesToHex(data));
                logEvent("bluetooth_classic_serial_write", jsonObject);
            }
        });

        findAndHookMethod("android.bluetooth.BluetoothInputStream", pck.classLoader, "read", byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);

                byte[] data = (byte[]) param.args[0];
                JSONObject jsonObject = new JSONObject()
                        .put("payload", bytesToHex(data));
                logEvent("bluetooth_classic_serial_read", jsonObject);
            }
        });
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

                JSONObject eventObject = new JSONObject()
                        .put("characteristic", characteristic.getUuid())
                        .put("payload", Base64.encodeToString(value, Base64.NO_WRAP));

                logEvent("ble_notify_characteristic", eventObject);
            }
        });
    }

    private void hookCipher(){
        XC_MethodHook cipherHook = new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);

                Cipher cipher = (Cipher) param.thisObject;

                String algorithm = cipher.getAlgorithm();
                String iv = Base64.encodeToString(cipher.getIV(), Base64.NO_WRAP);
                String input = Base64.encodeToString((byte[]) param.args[0], Base64.NO_WRAP);
                String result = Base64.encodeToString((byte[]) param.getResult(), Base64.NO_WRAP);

                Field opModeField = cipher.getClass().getDeclaredField("opmode");
                opModeField.setAccessible(true);
                int opmode = opModeField.getInt(cipher);
                boolean isEncrypting = opmode == Cipher.ENCRYPT_MODE;
                String eventType = isEncrypting ? "crypt_encrypt" : "crypt_decrypt";

                JSONObject eventObject = new JSONObject()
                        .put("algorithm", algorithm)
                        .put("input", input)
                        .put("result", result);

                logEvent(eventType, eventObject);
            }
        };

        findAndHookMethod(Cipher.class, "doFinal", byte[].class, cipherHook);
        findAndHookMethod(Cipher.class, "doFinal", byte[].class, int.class, int.class, cipherHook);

        findAndHookConstructor(IvParameterSpec.class, byte[].class, int.class, int.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                super.beforeHookedMethod(param);
                JSONObject eventObject = new JSONObject()
                        .put("iv", Base64.encodeToString((byte[]) param.args[0], Base64.NO_WRAP));
                logEvent("crypt_create_iv", eventObject);
            }
        });

        findAndHookMethod(KeyAgreement.class, "generateSecret", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);

                byte[] result = (byte[]) param.getResult();
                JSONObject resultObject = new JSONObject()
                        .put("result", Base64.encodeToString(result, Base64.NO_WRAP));

                logEvent("dh_result", resultObject);
            }
        });

        findAndHookMethod(KeyAgreement.class, "generateSecret", byte[].class, int.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);

                byte[] result = (byte[]) param.args[0];
                JSONObject resultObject = new JSONObject()
                        .put("result", Base64.encodeToString(result, Base64.NO_WRAP));

                logEvent("dh_result", resultObject);
            }
        });

        findAndHookMethod(KeyAgreement.class, "generateSecret", String.class, new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                super.afterHookedMethod(param);

                byte[] result = (byte[]) param.args[0];
                JSONObject resultObject = new JSONObject()
                        .put("algorithm", (String) param.args[0]);

                logEvent("dh_result", resultObject);
            }
        });
    }

    private void logEvent(String eventType, JSONObject eventDate){
        JSONObject fullObject = null;
        try {
            fullObject = new JSONObject()
                    .put("event", eventType)
                    .put("data", eventDate);

            log("event " + fullObject.toString());
        } catch (JSONException e) {
            log("error sending event");
            e.printStackTrace();
        }
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

                JSONObject eventObject = new JSONObject()
                        .put("characteristic", characteristic.getUuid())
                        .put("payload", Base64.encodeToString(characteristic.getValue(), Base64.NO_WRAP));

                logEvent("ble_write_characteristic", eventObject);
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

                JSONObject eventObject = new JSONObject()
                        .put("descriptor", descriptor.getUuid())
                        .put("payload", Base64.encodeToString(descriptor.getValue(), Base64.NO_WRAP));

                logEvent("ble_write_descriptor", eventObject);
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
