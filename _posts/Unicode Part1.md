---
title: "Technical analysis of an obfuscated XSS payload with cuneiform characters"
excerpt: "Technical analysis of an obfuscated XSS payload with cuneiform characters"
header:
  teaser: "/assets/images/Wirte.gif"
categories:
  - Blog 
---

# Análisis técnico de una carga XSS ofuscada con caracteres cuneiformes

La seguridad ofensiva en entornos web evoluciona constantemente. Los atacantes buscan formas creativas y técnicas avanzadas para evadir filtros, romper patrones de detección y ejecutar código malicioso en el navegador de la víctima. En este post realizamos un análisis profundo de una carga útil XSS escrita con **caracteres Unicode del sistema cuneiforme**, que resulta ser completamente válida en JavaScript.

---

## La carga útil

Este es el payload original:

```javascript
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```


## Fundamento técnico: ¿por qué esto funciona?

Para comprender cómo una carga útil como esta puede ser ejecutada sin errores en un navegador moderno, necesitamos entender algunos aspectos clave del lenguaje JavaScript que permiten este tipo de comportamiento. Esta sección explica los fundamentos técnicos que hacen posible este tipo de evasión.

---

### 1. Identificadores Unicode válidos en JavaScript

ECMAScript (el estándar de JavaScript) permite que los identificadores (nombres de variables, funciones, etc.) utilicen una amplia gama de caracteres Unicode, incluidos scripts antiguos como:

- Cuneiforme (U+12000–U+123FF)
- Egipcio jeroglífico
- Tifinagh
- Cirílico, griego, etc.

Esto significa que expresiones como las siguientes son perfectamente válidas:

```js
𒀀 = 123;
console.log(𒀀); // Output: 123
```

> 🔎 **Nota:** Este uso es legal pero no común, lo cual lo hace ideal para técnicas de evasión y ofuscación.

---

### 2. Coerción de tipos y generación de strings

JavaScript tiene un sistema de tipos muy flexible. Se puede forzar a los valores a convertirse en strings automáticamente, y eso se explota aquí para construir palabras clave (como `eval`, `Function`, etc.) a partir de operaciones aparentemente inocuas.

Ejemplos clave:

| Expresión       | Resultado      | Explicación                         |
|----------------|----------------|-------------------------------------|
| `+[]`          | `0`            | Operación unaria sobre arreglo vacío |
| `![]`          | `false`        | Negación lógica                     |
| `[] + []`      | `""`           | Dos arrays concatenados             |
| `{} + []`      | `"[object Object]"` | Objeto convertido a string        |
| `!{} + []`     | `"false"`      | Coerción lógica + string            |

Entonces, construcciones como estas:

```js
𒀀 = '';
𒉺 = !𒀀 + 𒀀;    // "true"
𒀃 = !𒉺 + 𒀀;    // "false"
𒇺 = 𒀀 + {};     // "[object Object]"
```

sirven para obtener cadenas desde expresiones booleanas o de objetos.

---

### 3. Acceso por índice para formar palabras

Después de generar las cadenas, el payload accede a ciertos caracteres mediante índices. Por ejemplo:

```js
𒉺 = "true"
𒉺[0] = 't'
𒉺[1] = 'r'
```

Este patrón se repite para construir las letras necesarias que forman las funciones críticas como `eval`, `Function`, etc.

---

### 4. Creación dinámica de funciones

Al combinar todas las letras, se llega a construir cadenas como `"eval"` o `"Function"` completamente sin escribirlas directamente. Luego se usa:

```js
window["eval"]("alert(1)")
```

O, en su forma completamente ofuscada:

```js
𒉺[𒁹](𒀀)
```

Donde `𒁹` es la cadena `"eval"` y `𒀀` es `"alert(1)"`.

---

### 5. Ejecución controlada mediante llamada dinámica

Finalmente, la ejecución del código se realiza al invocar indirectamente la función construida dinámicamente, lo cual permite que el payload pase desapercibido:

```js
(eval)(payload);
```

O incluso:

```js
(new Function("alert(1)"))();
```

Ambas son formas equivalentes de ejecutar código dinámico en JavaScript, y los atacantes eligen una u otra dependiendo del nivel de evasión que deseen.

---

## En resumen:

| Técnica                       | Propósito                            |
|------------------------------|--------------------------------------|
| Identificadores Unicode      | Evadir detección basada en patrones  |
| Coerción de tipos            | Generar cadenas desde valores base   |
| Acceso por índices           | Construir palabras clave sensibles   |
| Llamada dinámica             | Ejecutar funciones sin escribir sus nombres directamente |
| No uso de comillas ni `eval` visibles | Bypass a WAFs y parsers de seguridad |

Estas técnicas combinadas representan una forma altamente ofuscada y eficaz de ejecutar código malicioso en el navegador. Su entendimiento es clave para desarrollar defensas más robustas y análisis de tráfico más profundo.

---
