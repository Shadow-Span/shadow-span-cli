import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.io.ObjectInputStream;
import java.beans.XMLDecoder;
import java.util.Random;
import javax.xml.parsers.DocumentBuilderFactory;
public class Vuln {
  void cmd(String name) throws Exception { Runtime.getRuntime().exec("ls " + name); }
  void sql(java.sql.Statement st, String id) throws Exception { st.executeQuery("SELECT * FROM u WHERE id=" + id); }
  void sql2(java.sql.Statement st, String id) throws Exception { st.executeUpdate("DELETE FROM u WHERE id=" + id); }
  Object deser(ObjectInputStream noUse, java.io.InputStream in) throws Exception { return new ObjectInputStream(in).readObject(); }
  Object xmld(java.io.InputStream in) { return new XMLDecoder(in); }
  void xxe(DocumentBuilderFactory dbf) throws Exception { dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false); }
  void h1() throws Exception { MessageDigest.getInstance("MD5"); }
  void h2() throws Exception { MessageDigest.getInstance("SHA-1"); }
  void cph() throws Exception { Cipher.getInstance("DES/ECB/PKCS5Padding"); }
  Object tls() { return new NoopHostnameVerifier(); }
  int rnd() { return new Random().nextInt(); }
  Object ssrf(String b, String p) throws Exception { return new URL(b + p); }
  Object pt(String d, String n){ return new File(d + n); }
}
