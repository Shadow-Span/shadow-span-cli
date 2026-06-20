package main
import (
	"crypto/md5"; "crypto/sha1"; "crypto/des"; "crypto/rc4"; "crypto/tls"
	"database/sql"; "fmt"; "html/template"; "os/exec"
)
func tlsf() { _ = &tls.Config{ InsecureSkipVerify: true } }
func cmd(name string) { _ = exec.Command("sh", "-c", "ls "+name) }
func q(db *sql.DB, id string) { _, _ = db.Query(fmt.Sprintf("SELECT * FROM u WHERE id=%s", id)) }
func qe(db *sql.DB, id string) { _, _ = db.Exec(fmt.Sprintf("DELETE FROM u WHERE id=%s", id)) }
func xss(s string) template.HTML { return template.HTML(s) }
func h1() { _ = md5.New() }
func h1b(b []byte) { _ = md5.Sum(b) }
func h2() { _ = sha1.New() }
func cdes(k []byte) { _, _ = des.NewCipher(k) }
func crc4(k []byte) { _, _ = rc4.NewCipher(k) }
func ssrf(base, p string) { _, _ = http.Get(base + p) }
func pt(dir, name string) { _, _ = os.Open(dir + name) }
