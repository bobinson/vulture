import java.io.*;
import java.util.*;

class Pull {
    byte[] slurp(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] b = new byte[4096];
        int n;
        while ((n = in.read(b)) != -1) {
            // EXPECT-NEXT: finding read into an array until end of stream
            bos.write(b, 0, n);
        }
        return bos.toByteArray();
    }
    byte[] slurpData(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        int r;
        while ((r = in.read(data)) != -1) {
            // EXPECT-NEXT: finding read result compared with end of stream
            bos.write(data, 0, r);
        }
        return bos.toByteArray();
    }
    String chars(Reader rd) throws IOException {
        StringBuilder sb = new StringBuilder();
        char[] cbuf = new char[1024];
        int r;
        while ((r = rd.read(cbuf)) > 0) {
            // EXPECT-NEXT: finding char reads until none are left
            sb.append(cbuf, 0, r);
        }
        return sb.toString();
    }
    void configure(Properties props, List<String> paths, List<String> loaded) throws IOException {
        for (String p : paths) {
            // EXPECT-NEXT: clean a read of a path list is not a pull
            loaded.add(p);
        }
    }
    List<byte[]> frames(DataInputStream dis) throws IOException {
        List<byte[]> out = new ArrayList<>();
        while (true) {
            int len = dis.readInt();
            byte[] f = new byte[len];
            dis.readFully(f);
            // EXPECT-NEXT: clean known-gap: typed reads (readInt / readFully) are not pull roles (LLD 5.2.6)
            out.add(f);
        }
    }
}
