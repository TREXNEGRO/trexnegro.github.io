---
title: "Why two RSA moduli sharing a common factor breaks the cryptosystem"
date: 2024-03-19T12:00:00-05:00
draft: false
categories: [Cryptography, CTF]
tags: [rsa, htb, ctf, math, writeup]
description: "HackTheBox RSAiseazy challenge walkthrough. When two RSA moduli are not coprime, GCD recovers the shared prime — both keys collapse."
ShowReadingTime: true
ShowCodeCopyButtons: true
---
> Originally written in Spanish. Browser translate covers EN.

## Problema de seguridad en RSA

El problema de seguridad surge cuando dos módulos RSA no son primos entre sí. En RSA, la clave pública se representa como $(n, e)$, donde $n = p \cdot q$, siendo $p$ y $q$ dos números primos, y $e$ es el exponente de cifrado.

Supongamos que tenemos dos claves públicas distintas, $(n_A, e_A)$ y $(n_B, e_B)$, con $n_A \neq n_B$, y que $\gcd(n_A, n_B) \neq 1$. Esto significa que hay un divisor común de $n_A$ y $n_B$, lo cual es un problema porque $n_A$ y $n_B$ solo tienen dos divisores cada uno: los dos números primos que los componen.

Por lo tanto, $\gcd(n_A, n_B)$ es uno de los primos secretos de ambas claves, y los otros primos secretos son trivialmente $n_A / \gcd(n_A, n_B)$ y $n_B / \gcd(n_A, n_B)$.

Esto demuestra que es crítico que en una clave RSA, ambos primos sean únicos.

Saber un factor de los dos totientes puede o no revelar la clave privada. Si el factor que tienes es 4, eso no te da ninguna información: $(p-1)(q-1)$ siempre es un múltiplo de 4. Si el factor que tienes resulta ser $p-1$ o te permite encontrar $p-1$, eso obviamente es un problema. Pero dado que el totiente normalmente no se expone en ningún lugar, este no es un problema comúnmente preocupante.

## Ejemplo — HackTheBox RSAiseazy

Vamos a dividir el desafío en dos partes.

### Primera parte del desafío

La primera mitad del desafío es donde entra en juego el último dato proporcionado, el valor de:

$$\text{extraData} = n_1 \cdot E + n_2$$

Solo conocemos el valor de uno de los módulos ($n_1$), pero al proporcionarnos `extraData`, es otra forma de darnos $n_2$.

El truco está en darse cuenta de que:

$$\text{extraData} \bmod n_1 = (n_1 \cdot E + n_2) \bmod n_1 = n_2$$

En este punto, tenemos el módulo utilizado en ambas encripciones ($n_1$ y $n_2$).

### Segunda parte del desafío

La otra mitad del desafío se basa en el problema de seguridad que podría surgir cuando se utilizan dos módulos que no son primos entre sí para la encripción.

Básicamente, si $n_1$ y $n_2$ no son coprimos entre sí, eso significa que existe un $\gcd(n_1, n_2) > 1$.

Además, como $p$, $q$ y $z$ son primos, y $n_1 = p \cdot q$, $n_2 = q \cdot z$, la única posibilidad es que $\gcd(n_1, n_2) = q > 1$.

Esto nos permite calcular no solo $q$ sino también:

$$p = n_1 / q \qquad z = n_2 / q$$

Teniendo $p$, $q$ y $z$, podemos realizar dos veces las operaciones necesarias para descifrar el algoritmo de encripción RSA:

Se obtiene la clave privada:

- $d_1 = e^{-1} \pmod{(p-1)(q-1)}$ para la primera desencripción
- $d_2 = e^{-1} \pmod{(q-1)(z-1)}$ para la segunda desencripción

## Resumen

Cuando dos módulos RSA comparten un factor primo, ambas claves colapsan simultáneamente:

- `gcd()` recupera el primo compartido en $O(\log n)$.
- Ambas claves privadas se reconstruyen trivialmente.

Lección operacional: la entropía de generación de primos debe estar fully isolated entre instancias. Esto históricamente ha fallado en routers embedded (Heninger et al., 2012 — "Mining Your Ps and Qs") donde el RNG de primos compartía estado en dispositivos del mismo lote.
