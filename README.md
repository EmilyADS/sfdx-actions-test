versionPackage=2.2.1.latest.2HD962xo*dR31lSMPYy
versionProd=2.2.3.10

vercomp () {
    if [[ $1 == $2 ]]
    then
        #echo "$1 é igual a $2"
        return 0
    fi
    local IFS=.
    local i ver1=($1) ver2=($2)
    # fill empty fields in ver1 with zeros
    for ((i=${#ver1[@]}; i<${#ver2[@]}; i++))
    do
        ver1[i]=0
    done
    for ((i=0; i<3; i++))
    do
        if [[ -z ${ver2[i]} ]]
        then
            # fill empty fields in ver2 with zeros
            ver2[i]=0
        fi
        if ((10#${ver1[i]} > 10#${ver2[i]}))
        then
           # echo "$1 (${ver1[i]}) é maior que prod $2 (${ver2[i]})"
            # ele olha item por item, se tirar o return vai continuar olhando os demais
            return 1
        fi
        if ((10#${ver1[i]} < 10#${ver2[i]}))
        then
            echo "$1 (${ver1[i]}) é menor que prod $2 (${ver2[i]})"
            versions_lower_count=$((versions_lower_count + 1 ))
            return 2
        fi
    done
    echo "Analise finalizada"
    return 0
}

versions_1="2.2.0 1.1.0 2.3.4"
versions_2="2.2.0 1.3.0 2.3.4"
versions_lower_count=0
for v1 in $versions_1; do
    for v2 in $versions_2; do
        echo "v1 = $v1 / v2 = $v2"
       vercomp $v1 $v2
    #   vercomp_result=$?
        
    #     if [ $vercomp_result -eq 2 ]; then
    #       versions_lower_count=$((versions_lower_count + 1 ))
    #     fi
    done;
done;
# vercomp $versionPackage $versionProd

#echo "existem $versions_lower_count pacotes com versão abaixo de prod, favor olhar o log acima"
vercomp_result=$?
 if [ $versions_lower_count -gt 0 ]; then
   echo "existem $versions_lower_count pacotes com versão abaixo de prod, favor olhar o log acima"
fi
