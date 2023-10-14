Puściłem scan nmap.
```
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4:b4:46:17:d2:10:2d:8f:ec:1d:c9:27:fe:cd:79:ee (RSA)
|   256 2a:ea:2f:cb:23:e8:c5:29:40:9c:ab:86:6d:cd:44:11 (ECDSA)
|_  256 fd:78:c0:b0:e2:20:16:fa:05:0d:eb:d8:3f:12:a4:ab (ED25519)
80/tcp open  http    nginx 1.18.0
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-title: MetaPress &#8211; Official company site
|_http-server-header: nginx/1.18.0
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-generator: WordPress 5.6.2
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94%I=7%D=10/14%Time=652A9704%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10
SF:\.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cr
SF:eative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creativ
SF:e\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Wordpress działa na 80 porcie, i widzimy również jakiś ciekawy komunikat XML parsing, przyjrzymy się to póżniej. 
Musimy dodać domene do /etc/hosts. echo "10.10.11.186 metapress.htb" >> /etc/hosts
Teraz możemy wejść na stronę.

![obraz](https://github.com/Anogota/MetaTwo/assets/143951834/4bd27696-0578-4f35-a52d-62e75eeb2422)

Widzimy tylko jest to zachęta aby tam wejśc, coś tam się musi kryć. Odpaliłem burp aby prześledzić trochę ruchu co tam się ciekawe dzieje.
W przechwyconym pakiecie widzimy ciekawe rzeczy.

![obraz](https://github.com/Anogota/MetaTwo/assets/143951834/1192b56b-bfb0-4756-8ce5-f983be20021a)

Warto zapmiętać. Również możemy dostrzeć tam bibliotekę WordPress'a

![obraz](https://github.com/Anogota/MetaTwo/assets/143951834/54957ad8-8b55-4711-8d47-1d464682eed3)

Przejdżmy teraz do googlowania odnośnie tej wersji Wordpress'a oraz tej biblioteki.
Znalazłem CVE dla tej wersji wordpress, tylko musimy mieć dostęp do panelu, czyli musimy skąść wytrzasnąć poświadczenia do zalogowania się.
```
https://blog.wpsec.com/wordpress-xxe-in-media-library-cve-2021-29447/
```
Teraz coś poszukajmy odnośnie tej biblioteki.
