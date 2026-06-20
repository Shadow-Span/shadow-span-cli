using System;
using System.Diagnostics;
using System.Data.SqlClient;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Xml;
using System.Net;
class Vuln {
  void Cmd(string c){ Process.Start(c); }
  void Sql(string id){ var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id); }
  void Sql2(string id){ var cmd = new SqlCommand($"SELECT * FROM u WHERE id={id}"); }
  object Deser(System.IO.Stream s){ var f = new BinaryFormatter(); return f.Deserialize(s); }
  void Xxe(XmlReaderSettings st){ st.DtdProcessing = DtdProcessing.Parse; }
  void H1(){ var m = MD5.Create(); }
  void H1b(){ var m = new MD5CryptoServiceProvider(); }
  void H2(){ var s = SHA1.Create(); }
  void Cph(){ var d = DES.Create(); }
  void Tls(){ ServicePointManager.ServerCertificateValidationCallback = (a,b,c,d) => true; }
  int Rnd(){ return new Random().Next(); }
  object Ssrf(string b, string p){ return WebRequest.Create(b + p); }
  string Pt(string d, string n){ return File.ReadAllText(d + n); }
}
