---
title: "Acerca"
url: "/es/about/"
summary: acerca
layout: "single"
ShowReadingTime: false
ShowToc: false
ShowBreadCrumbs: false
hideMeta: true
---

> La mayor parte del contenido está en **inglés**. Usá el botón del globo arriba a la derecha para cambiar idioma. Los posts originalmente en español tienen el tag `lang:es`.

## SixSixSix

Investigación independiente de seguridad ofensiva.

### Enfoque

- Explotación del kernel Linux — primitivas softirq, backport-gap, stacks RDMA/iSCSI/SMB
- Evasión EDR / endpoint — patchless AMSI/ETW bypass, sidestepping de proveedores ETW, hand-off user → kernel
- Active Directory — recolección LDAP sin `wldap32`, evasión del provider-LDAP
- Web app & API — composición de cadenas de autenticación (low + low = P1), colisiones SAML/OAuth/SSO
- Mobile — fuzzing de intents Android, servicios de sistema Pixel

### Disclosure

Caminos de coordinación:

- Kernel Linux — `linux-cve-announce@`, `security@kernel.org`
- Android — Google ASR
- PSIRT de vendor / programas selectos de bug bounty
- ZDI para disclosures pagados cuando aplique

Para disclosures sensibles, prefiero canales encriptados. Llave PGP disponible bajo pedido vía el inbox de abajo.

### Contacto

Llave PGP y dirección de contacto bajo pedido vía issue en este repositorio.

---

### Colofón

Construido con [Hugo](https://gohugo.io) + el theme [PaperMod](https://github.com/adityatelange/hugo-PaperMod). Hosteado en GitHub Pages.
