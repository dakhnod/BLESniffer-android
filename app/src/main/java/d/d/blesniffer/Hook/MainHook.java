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
import java.util.HashMap;
import java.util.List;

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
