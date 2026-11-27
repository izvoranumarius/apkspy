// Source of tests/emu_fixture.inc, second class: code for the decompiler naming, nesting, logging and rename tests.
import android.util.Log;

public class UiFix {
    static int title;
    static String secretValue;

    static String getAuthToken() {
        return secretValue;
    }

    static int nested(int a, int b) {
        if (a > 0) {
            if (b > 0) {
                title = 0x7f010000;
            }
        }
        if (a == 7) {
            return 1;
        } else {
            title += b;
        }
        return title;
    }

    static void logs(String user) {
        Log.d("net", "starting");
        Log.d("auth", "token=" + getAuthToken());
        Log.i("ui", "clicked " + user.length());
        Log.w("pw", "password is wrong");
    }

    static String read() {
        return secretValue;
    }

    static void sink(String line) {
        Log.d("w", line);
    }

    // Names here say nothing: only following the data finds what is logged.
    static void flows(java.util.Map<String, String> store) {
        String x = read();
        StringBuilder b = new StringBuilder();
        b.append("value ").append(x);
        Log.d("a", b.toString());
        String y = store.get("session_token");
        Log.d("b", "got " + y);
        Log.d("c", "size " + x.length());
        sink(x);
    }

    // Stored in one place, logged in another: fields with names that say nothing, a setter, and lists.
    static String cached;
    static String other;
    static java.util.List<String> bag = new java.util.ArrayList<>();

    @SuppressWarnings("deprecation")
    static void remember(android.telephony.TelephonyManager t) {
        cached = t.getDeviceId();
    }

    static void store(String v) {
        other = v;
    }

    static void storeImei(android.telephony.TelephonyManager t) {
        store(t.getImei());
    }

    static void collect(java.util.List<String> into, android.telephony.TelephonyManager t) {
        into.add(t.getSubscriberId());
    }

    static void later(android.telephony.TelephonyManager t) {
        Log.d("d", "v=" + cached);
        Log.d("e", "o=" + other);
        java.util.List<String> mine = new java.util.ArrayList<>();
        collect(mine, t);
        Log.d("f", "l=" + mine.get(0));
        bag.add(t.getLine1Number());
    }

    static void dump() {
        Log.d("g", "bag " + bag);
    }

    static int caller(int a) {
        return nested(a, title);
    }
}
