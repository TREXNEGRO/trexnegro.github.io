---
title: "Why is it a security problem that two RSA modules are not co-prime?"
excerpt: "¿Por qué es un problema de seguridad que dos módulos RSA no sean coprimarios?"
header:
  teaser: "/assets/images/Wirte.gif"
categories:
  - Blog
---
## Problema de seguridad en RSA

El problema de seguridad surge cuando dos módulos RSA no son primos entre sí. En RSA, la clave pública se representa como *(n, e)*, donde *n = pq*, siendo *p* y *q* dos números primos, y *e* es el exponente de cifrado.

Supongamos que tenemos dos claves públicas distintas, *(n<sub>A</sub>, e<sub>A</sub>)* y *(n<sub>B</sub>, e<sub>B</sub>)*, con *n<sub>A</sub> ≠ n<sub>B</sub>*, y que *gcd(n<sub>A</sub>, n<sub>B</sub>) ≠ 1*. Esto significa que hay un divisor común de *n<sub>A</sub>* y *n<sub>B</sub>*, lo cual es un problema porque *n<sub>A</sub>* y *n<sub>B</sub>* solo tienen dos divisores cada uno: los dos números primos que los componen. Por lo tanto, *gcd(n<sub>A</sub>, n<sub>B</sub>)* es uno de los primos secretos de ambas claves, y los otros primos secretos son trivialmente *n<sub>A</sub>/gcd(n<sub>A</sub>, n<sub>B</sub>)* y *n<sub>B</sub>/gcd(n<sub>A</sub>, n<sub>B</sub>)*.

Esto demuestra que es crítico que en una clave RSA, ambos primos sean únicos.

Saber un factor de los dos totientes puede o no revelar la clave privada. Si el factor que tienes es 4, eso no te da ninguna información: *(p-1)(q-1)* siempre es un múltiplo de 4. Si el factor que tienes resulta ser *p-1* o te permite encontrar *p-1*, eso obviamente es un problema. Pero dado que el totiente normalmente no se expone en ningún lugar, este no es un problema comúnmente preocupante.

## Ejemplo

Usaremos para ejemplificar el Challege de HackTheBox RSAiseazy

Vamos a dividir el desafío en dos partes.

**Primera parte del desafío:**

La primera mitad del desafío es donde entra en juego el último dato proporcionado, el valor de `extraData = n1 * E + n2`.

Solo conocemos el valor de uno de los módulos (n1), pero, con un poco de análisis, al proporcionarnos extraData, es otra forma de darnos n2.

El truco está en darse cuenta de que `extraData % n1 = (n1 * E + n2) % n1 = n2`. 

En este punto, tenemos el módulo utilizado en ambas encripciones (n1 y n2).

**Segunda parte del desafío:**

La otra mitad del desafío se basa en el problema de seguridad que podría surgir cuando se utilizan dos módulos que no son primos entre sí para la encripción.

Básicamente, si n1 y n2 no son coprimos entre sí, eso significa que existe un gcd(n1,n2) > 1.

Además, como p, q y z son primos, y n1 = p * q, n2 = q * z, la única posibilidad es que gcd(n1,n2) = q > 1.

Esto nos permite calcular no solo q sino también: p = n1 / q y z = n2 / q.

Teniendo p, q y z, podemos realizar dos veces las operaciones necesarias para descifrar el algoritmo de encripción RSA:

Se obtiene la clave privada:
- d1 = inverso multiplicativo modular(e, (p-1)*(q-1)) para la primera desencripción.
- d2 = inverso multiplicativo modular(e, (q-1)*(z-1)) para la segunda desencripción.

Se calcula el texto plano:
- flag1 = pow(c1, d1, n1) para el primer caso.
- flag2 = pow(c2, d2, n2) para el segundo caso.

para poder resolver podemos usar el siguiente codigo en python:

```python
#!/usr/bin/python3
import math
import gmpy2
from gmpy2 import mpz

e = mpz('0x10001')
n1 = mpz('101302608234750530215072272904674037076286246679691423280860345380727387460347553585319149306846617895151397345134725469568034944362725840889803514170441153452816738520513986621545456486260186057658467757935510362350710672577390455772286945685838373154626020209228183673388592030449624410459900543470481715269')
c1 = mpz('92506893588979548794790672542461288412902813248116064711808481112865246689691740816363092933206841082369015763989265012104504500670878633324061404374817814507356553697459987468562146726510492528932139036063681327547916073034377647100888763559498314765496171327071015998871821569774481702484239056959316014064')
c2 = mpz('46096854429474193473315622000700040188659289972305530955007054362815555622172000229584906225161285873027049199121215251038480738839915061587734141659589689176363962259066462128434796823277974789556411556028716349578708536050061871052948425521408788256153194537438422533790942307426802114531079426322801866673')
extraData = mpz('601613204734044874510382122719388369424704454445440856955212747733856646787417730534645761871794607755794569926160226856377491672497901427125762773794612714954548970049734347216746397532291215057264241745928752782099454036635249993278807842576939476615587990343335792606509594080976599605315657632227121700808996847129758656266941422227113386647519604149159248887809688029519252391934671647670787874483702292498358573950359909165677642135389614863992438265717898239252246163')

# ----------------------------
# Firts hald of the solution
n2 = extraData % n1

# ----------------------------
# Second hald of the solution
q = gmpy2.gcd(n1, n2)

p = gmpy2.c_div(n1, q)
z = gmpy2.c_div(n2, q)

d1 = gmpy2.invert(e, (p-1)*(q-1))
d2 = gmpy2.invert(e, (q-1)*(z-1))

flag1 = pow(c1, d1, n1)
flag2 = pow(c2, d2, n2)

# ----------------------------

flag1_bytes = gmpy2.to_binary(flag1)
flag2_bytes = gmpy2.to_binary(flag2)

flag1_string = flag1_bytes.decode('utf-8')
flag2_string = flag2_bytes.decode('utf-8')

print(flag1_string[::-1] + flag2_string[::-1])

```

La Flag es "HTB{1_m1ght_h4v3_m3ss3d_uP_jU$t_4_l1ttle_b1t?}"