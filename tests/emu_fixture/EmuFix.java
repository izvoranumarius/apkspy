// Source of tests/emu_fixture.inc (compiled with javac --release 8 and d8): routines for the string-decoder
// interpreter. The expected results in the platform test are what the host JVM returns for the same calls.
import java.lang.reflect.Method;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class EmuFix {
    static class Bad extends RuntimeException {
        Bad(String message) {
            super(message);
        }
    }

    static int divide(int a, int b) {
        return a / b;
    }

    public static String exceptions(String s) {
        StringBuilder out = new StringBuilder();
        try {
            out.append(Integer.parseInt(s));
        } catch (NumberFormatException e) {
            out.append("nan");
        }
        try {
            throw new Bad("bad " + s);
        } catch (IllegalStateException e) {
            out.append(",wrong");
        } catch (RuntimeException e) {
            out.append(',').append(e.getMessage());
        }
        try {
            out.append(divide(1, s.length() - s.length()));
        } catch (ArithmeticException e) {
            out.append(",div");
        } finally {
            out.append(",finally");
        }
        try {
            out.append(new int[2][0 + s.length()].length);
            byte[] b = new byte[1];
            out.append(b[s.length()]);
        } catch (Exception e) {
            out.append(",caught");
        }
        try {
            Object o = null;
            o.toString();
        } catch (NullPointerException e) {
            out.append(",null");
        }
        return out.toString();
    }

    public static String uncaught(String s) {
        throw new IllegalStateException("boom " + s);
    }

    static String shout(String s, int times) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < times; i++) b.append(s.toUpperCase());
        return b.toString();
    }

    public static String reflect(String s) {
        try {
            Method charAt = String.class.getMethod("charAt", int.class);
            Character first = (Character) charAt.invoke(s, 1);
            Method own = Class.forName("EmuFix").getDeclaredMethod("shout", String.class, int.class);
            own.setAccessible(true);
            String loud = (String) own.invoke(null, s, 2);
            Method max = Class.forName("java.lang.Math").getMethod("max", int.class, int.class);
            int m = (Integer) max.invoke(null, 4, 9);
            String[] parts = {String.valueOf(first.charValue()), loud, Integer.toString(m), EmuFix.class.getSimpleName()};
            StringBuilder out = new StringBuilder();
            for (String p : parts) out.append(p).append(';');
            return out.toString();
        } catch (Exception e) {
            return "failed " + e;
        }
    }

    static String hex(byte[] b) {
        char[] digits = "0123456789abcdef".toCharArray();
        StringBuilder out = new StringBuilder();
        for (byte x : b) out.append(digits[(x >> 4) & 15]).append(digits[x & 15]);
        return out.toString();
    }

    public static String gcm(String s) {
        try {
            SecretKeySpec key = new SecretKeySpec("0123456789abcdef".getBytes("UTF-8"), "AES");
            GCMParameterSpec iv = new GCMParameterSpec(128, "unique nonce".getBytes("UTF-8"));
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, key, iv);
            c.updateAAD("header".getBytes("UTF-8"));
            byte[] sealed = c.doFinal(s.getBytes("UTF-8"));
            c.init(Cipher.DECRYPT_MODE, key, iv);
            c.updateAAD("header".getBytes("UTF-8"));
            String back = new String(c.doFinal(sealed), "UTF-8");
            String tampered;
            try {
                sealed[0] ^= 1;
                c.init(Cipher.DECRYPT_MODE, key, iv);
                c.doFinal(sealed);
                tampered = "accepted";
            } catch (javax.crypto.BadPaddingException e) {
                tampered = "rejected";
            }
            sealed[0] ^= 1;
            return hex(sealed) + "|" + back + "|" + tampered;
        } catch (Exception e) {
            return "failed " + e;
        }
    }

    interface Step {
        char apply(char c);
    }

    static class Shift implements Step {
        final int by;

        Shift(int by) {
            this.by = by;
        }

        public char apply(char c) {
            return (char) (c + by);
        }

        String name() {
            return "shift" + by;
        }
    }

    static class Twice extends Shift {
        int used;

        Twice(int by) {
            super(by);
        }

        @Override
        public char apply(char c) {
            used++;
            return super.apply(super.apply(c));
        }

        @Override
        String name() {
            return "twice-" + super.name();
        }
    }

    static class Holder {
        static Holder last;
        private final Step[] steps;
        private final StringBuilder out = new StringBuilder();

        Holder(Step... steps) {
            this.steps = steps;
            last = this;
        }

        Holder run(String s) {
            for (int i = 0; i < s.length(); i++) out.append(steps[i % steps.length].apply(s.charAt(i)));
            return this;
        }

        private String text() {
            return out.toString();
        }
    }

    public static String objects(String s) {
        Twice twice = new Twice(2);
        Holder h = new Holder(new Shift(1), twice).run(s);
        Shift asBase = twice;
        Object o = twice;
        String kind = (o instanceof Step ? "step," : "") + (o instanceof Shift ? "shift," : "") + (o instanceof Holder ? "holder" : "other");
        try {
            Method name = Shift.class.getDeclaredMethod("name");
            return h.text() + "|" + asBase.name() + "|" + twice.used + "|" + twice.by + "|" + kind + "|" + name.invoke(asBase)
                    + "|" + (Holder.last == h);
        } catch (Exception e) {
            return "failed " + e;
        }
    }

    // Floating point: arithmetic, comparisons, conversions with Java's saturation, Float / Double text and bits, Math.
    public static String numbers(String s) {
        float f = s.length() * 1.5f;
        double d = s.charAt(0) / 3.0;
        double half = -2.5;
        float zero = s.length() - s.length();
        StringBuilder b = new StringBuilder();
        b.append(f).append('|').append(d).append('|').append((int) (d * 100)).append('|').append(Math.round(half)).append('|')
                .append(Math.round(2.5f)).append('|').append(f / zero).append('|').append(zero / zero == zero / zero).append('|')
                .append((int) (zero / zero)).append('|').append((long) (d * 1e30)).append('|').append(Float.floatToIntBits(f)).append('|')
                .append(Double.doubleToLongBits(d)).append('|').append(d / 1e7).append('|').append(d * 1e7).append('|')
                .append(Float.parseFloat("3.25")).append('|').append(Math.sqrt(d * d)).append('|').append(Math.max(-zero, zero)).append('|')
                .append(Math.min(-zero, zero)).append('|').append(d % 2).append('|').append(f > d ? "gt" : f < d ? "lt" : "eq").append('|')
                .append(Integer.toBinaryString(-8 * s.length())).append('|').append(Long.toHexString(-s.length())).append('|')
                .append(Integer.parseInt("-ff", 16)).append('|').append(Double.valueOf(d).intValue()).append('|').append((float) d).append('|')
                .append(Float.valueOf(f).equals(f)).append('|').append(String.valueOf(1.0 / 3)).append('|').append(Long.parseLong("123456789012"));
        char[] out = new char[s.length()];
        for (int i = 0; i < s.length(); i++) out[i] = (char) (s.charAt(i) + (int) Math.floor(Math.pow(2, i % 3) + 0.5));
        return b.append('|').append(out).toString();
    }

    // java.util: lists, HashMap / HashSet in their table order, LinkedHashMap in insertion order, iterators and boxes.
    public static String collections(String s) {
        List<String> parts = new ArrayList<>();
        for (String p : s.split(",")) parts.add(p);
        Map<String, Integer> counts = new HashMap<>();
        for (String p : parts) counts.put(p, counts.containsKey(p) ? counts.get(p) + 1 : 1);
        Map<String, String> ordered = new LinkedHashMap<>();
        for (int i = parts.size() - 1; i >= 0; i--) ordered.put(parts.get(i), "#" + i);
        Set<Integer> seen = new HashSet<>();
        for (char c : s.toCharArray()) seen.add((int) c);
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, Integer> e : counts.entrySet()) b.append(e.getKey()).append('=').append(e.getValue()).append(';');
        b.append('|').append(ordered).append('|').append(seen.size()).append('|');
        for (int v : seen) b.append((char) v);
        Iterator<String> it = ordered.keySet().iterator();
        b.append('|').append(it.next()).append('|').append(parts.indexOf("b")).append('|').append(parts.contains("zz"));
        parts.remove(0);
        b.append('|').append(parts).append('|').append(counts.get("nope"));
        Map<Integer, String> many = new HashMap<>();
        for (int i = 0; i < 40; i++) many.put(i * 37 + 5, "v" + i);
        int first = many.keySet().iterator().next();
        return b.append('|').append(first).append('|').append(many.size()).toString();
    }

    static final String FOR_OAEP = "@FOR_OAEP@";  // RSA/ECB/OAEPWithSHA-256AndMGF1Padding, encrypted by the JDK

    public static String oaep(String s) {
        try {
            KeyFactory f = KeyFactory.getInstance("RSA");
            PublicKey pub = f.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY)));
            PrivateKey priv = f.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY)));
            Cipher named = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
            named.init(Cipher.DECRYPT_MODE, priv);
            String fromJdk = new String(named.doFinal(Base64.getDecoder().decode(FOR_OAEP)), "UTF-8");
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
            Cipher c = Cipher.getInstance("RSA/ECB/OAEPPadding");
            c.init(Cipher.ENCRYPT_MODE, pub, spec);
            byte[] sealed = c.doFinal(s.getBytes("UTF-8"));
            c.init(Cipher.DECRYPT_MODE, priv, spec);
            String round = new String(c.doFinal(sealed), "UTF-8");
            Cipher v15 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            v15.init(Cipher.ENCRYPT_MODE, pub);
            byte[] box = v15.doFinal(s.getBytes("UTF-8"));
            v15.init(Cipher.DECRYPT_MODE, priv);
            return fromJdk + "|" + round + "|" + sealed.length + "|" + new String(v15.doFinal(box), "UTF-8");
        } catch (Exception e) {
            return "failed " + e;
        }
    }

    static final String PUBLIC_KEY = "@PUBLIC@";
    static final String PRIVATE_KEY = "@PRIVATE@";
    static final String FOR_PRIVATE = "@FOR_PRIVATE@";  // encrypted with the public key

    public static String rsa(String s) {
        try {
            KeyFactory f = KeyFactory.getInstance("RSA");
            PublicKey pub = f.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(PUBLIC_KEY)));
            PrivateKey priv = f.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIVATE_KEY)));
            Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(Cipher.ENCRYPT_MODE, priv);
            byte[] signedStyle = c.doFinal(s.getBytes("UTF-8"));
            c.init(Cipher.DECRYPT_MODE, pub);
            String one = new String(c.doFinal(signedStyle), "UTF-8");
            c.init(Cipher.DECRYPT_MODE, priv);
            String two = new String(c.doFinal(Base64.getDecoder().decode(FOR_PRIVATE)), "UTF-8");
            return hex(signedStyle).substring(0, 32) + "|" + one + "|" + two;
        } catch (Exception e) {
            return "failed " + e;
        }
    }
}
