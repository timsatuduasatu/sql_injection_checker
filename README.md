# sql_injection_checker
SQLInjectionChecker adalah sebuah pustaka PHP yang digunakan untuk mendeteksi serangan SQL Injection pada input pengguna. Pustaka ini menggabungkan penggunaan regular expression (regex), Trie automaton, dan algoritma Aho-Corasick untuk melakukan deteksi.

Pada awalnya, pustaka ini memungkinkan pengguna untuk menambahkan kata kunci standar atau regex yang terkait dengan serangan SQL Injection.

Kemudian, pustaka ini membangun sebuah Trie automaton dari kata kunci yang ditambahkan. Trie automaton digunakan untuk mencocokkan input pengguna dengan kata kunci yang telah ditentukan.

Selain itu, pustaka ini juga menggunakan regex untuk mencocokkan pola kata kunci yang lebih kompleks pada input pengguna.

Ketika input pengguna diterima, pustaka ini memeriksa apakah terdapat kecocokan dengan kata kunci pada Trie automaton dan regex yang telah ditentukan.

Jika serangan SQL Injection terdeteksi, pustaka ini mencatat pesan kesalahan dan memberikan peringatan kepada pengguna melalui tab terapung atau tab popup di browser.

Selain itu, pustaka ini juga dapat melakukan log pesan kesalahan ke file, sesuai dengan kebutuhan pengguna.

Metode Aho-Corasick juga digunakan untuk meningkatkan efisiensi dalam mencocokkan kata kunci pada input pengguna.

Dengan menggunakan SQLInjectionChecker, pengembang dapat dengan mudah meningkatkan keamanan aplikasi web mereka dengan mendeteksi serangan SQL Injection pada input pengguna menggunakan kombinasi regex, Trie automaton, dan algoritma Aho-Corasick.