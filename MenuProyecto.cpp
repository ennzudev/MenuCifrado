#include <iostream>
#include <fstream>
#include "Conio.h"
#include <stdio.h>
#include "sodium.h"
#include <vector>
#include <string.h>

using namespace std;
int main() {
    int choice = 0;
    unsigned char* key;
    unsigned char* nounce;
    unsigned char* cifrado;

    key = (unsigned char*)malloc(crypto_stream_chacha20_KEYBYTES);
    nounce = (unsigned char*)malloc(crypto_stream_chacha20_NONCEBYTES);
    randombytes_buf(nounce, crypto_stream_chacha20_NONCEBYTES);
    cifrado = (unsigned char*)malloc(crypto_stream_chacha20_NONCEBYTES);
    unsigned char hash[crypto_generichash_BYTES];
    int mlen;

    string tmp, tmp2, txt, txt2, nombre;
    const char* clave;
    const char* info;
    choice = 0;
    while (choice != 7) {
        cout << "\nSelecciona uno de los procedimientos: \n\n1 - Generacion de Clave\n2 - Recuperacion de Clave\n3 - Cifrado de Archivos\n4 - Descifrado de Archivos\n5 - Firma de Archivos\n6 - Verificacion de Firma de Archivos\n\nEleccion: ";
        cin >> choice;
        if (choice == 1) {
            printf("Generacion de Clave: \n");
            randombytes_buf(key, crypto_stream_chacha20_KEYBYTES);
            ofstream file;
            cout << "¿Como se va a llamar el documento? \n";
            cin >> nombre;
            file.open("archivos/" + nombre);
            file << key;
            file.close();
        }
        if (choice == 2) {
            printf("Recuperacion de Clave: \n");
            cout << "¿Como se llama el documento? \n";
            cin >> nombre;
            string nombreArchivo = ("archivos/" + nombre);
            ifstream pwd(nombreArchivo.c_str());
            while (!pwd.eof()) {
                pwd >> tmp2;
                txt2 += " " + tmp2;
            };
            pwd.close();
            clave = txt2.c_str();
            printf("\nClave: %s \n\n", clave);
        }
        if (choice == 3) {
            printf("Cifrado de Archivos: \n");
            cout << "¿Como se llama el documento? \n";
            cin >> nombre;
            string nombreArchivo = ("archivos/" + nombre);
            ifstream archivo(nombreArchivo.c_str());
            while (!archivo.eof()) {
                archivo >> tmp;
                txt += " " + tmp;
            };
            archivo.close();
            info = txt.c_str();
            const unsigned char* txt3;
            txt3 = (const unsigned char*)info;
            randombytes_buf(nounce, crypto_stream_chacha20_NONCEBYTES);
            mlen = sizeof(txt3);
            crypto_stream_chacha20_xor(cifrado, txt3, mlen, nounce, key);
            ofstream file;
            file.open("archivos/cifrado.txt");
            file << cifrado;
            file.close();
            printf("\nArchivo cifrado.\n");
        }
        if (choice == 4) {
            printf("Descifrado de Archivos: \n");
            cin >> nombre;
            string nombreArchivo = ("archivos/" + nombre);
            ifstream archivo(nombreArchivo.c_str());
            while (!archivo.eof()) {
                archivo >> tmp;
                txt += " " + tmp;
            };
            archivo.close();
            info = txt.c_str();
            unsigned char* txt3;
            txt3 = (unsigned char*)info;
            mlen = sizeof(txt3);
            crypto_stream_chacha20_xor(txt3, cifrado, mlen, nounce, key);
            ofstream file;
            file.open("archivos/decifrado.txt");
            file << txt3;
            file.close();
            printf("\nArchivo decifrado.\n");
        }
        if (choice == 5) {
            unsigned char client_pk[crypto_kx_PUBLICKEYBYTES], client_sk[crypto_kx_SECRETKEYBYTES];
            unsigned char client_rx[crypto_kx_SESSIONKEYBYTES], client_tx[crypto_kx_SESSIONKEYBYTES];
            crypto_kx_keypair(client_pk, client_sk);
            unsigned char server_pk[crypto_kx_PUBLICKEYBYTES], server_sk[crypto_kx_SECRETKEYBYTES];
            if (crypto_kx_client_session_keys(client_rx, client_tx, client_pk, client_sk, server_pk) != 0) {
                exit(1);
            }
            unsigned char* reto = (unsigned char*)(txt.c_str());
            unsigned char IDalice[(sizeof(txt) + 14)] = "is721596@iteso.mx";
            for (int i = 14; i < sizeof(txt); i++) {
                IDalice[i] = reto[i - 14];
            }
            std::cout << std::endl;
            unsigned char MAC[crypto_auth_hmacsha512_BYTES];
            crypto_auth_hmacsha512(MAC, IDalice, (sizeof(txt) + 14), client_tx);
            cout << "\nFirma: " << MAC << " \n";
        }
        if (choice == 6) {
            cout << "Verificación pendiente: \n";
            //openssl verify - CAfile rootcert.pem newcert.pem
            //unsigned char server_rx[crypto_kx_SESSIONKEYBYTES], server_tx[crypto_kx_SESSIONKEYBYTES];
            //crypto_kx_keypair(server_pk, server_sk);
            /*if (crypto_kx_client_session_keys(server_rx, server_tx, server_pk, server_sk, client_pk) != 0) {
                exit(1);
            } */
        }
    }
    cout << "-- SALIR --\n";
}
