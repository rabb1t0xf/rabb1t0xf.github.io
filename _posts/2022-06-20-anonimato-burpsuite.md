---
title: Socks Burpsuite
author: rabb1t0xf
date: 2022-06-01
categories: [Burpsuite]
tags: [Socks, Anonimato]
math: true
mermaid: true
image:
  path: /assets/favicon/ctf.png
  width: 100
  height: 100
---
El día de hoy, y como primer artículo haremos algo sencillo: aprenderemos a cómo interceptar y enviar peticiones de una forma un tanto diferente a lo habitual. A través de Burpsuite ¿Por qué diferente? Pues bien, vamos a usar proxychains y tor como proxy. Sí, será un proxy que interceptará datos provenientes de otro proxy, se estarán pasando los "paquetitos" como una cadena ¿A poco no suena fascinante? Esto lo haremos con la intención de anonimizar peticiones que enviaremos y recibiremos al hacer pruebas desde el favorito de muchos (por no decir de todos) *'Burpsuite'*.

> No seré de aquellos que te digan qué es un __proxy__, una petición o __tor__ (por lo menos no en un artículo dirigido a un tema en específico como este) para ello tienes diverso material en internet, aunque si quieres que lo explique en un artículo, házmelo saber y sin rechistar lo haré lo más ameno y pronto posible.

Pero bien seguro que has venido para configurar esto y ser un poco más sigiloso o anónimo (lo que muchos quisieramos) antes que leer algo denso así que vayamos a ello:

[Ver cómo instalar las herramientas de este artículo](https://rabbit.github.io/posts/instalacion-de-herramientas)

Cuando tengamos las herramientas instaladas procedemos a verificar que la configuración de proxychains esté bien por defecto como os muestro a continuación:

### aquí van imágenes

Activamos el servicio de tor (por defecto está en escucha por el puerto 9050)
```shell
systemctl enabled tor 
systemctl start tor
```

Verificamos que el servicio está corriendo con cualquiera de los siguientes comandos y filtrando con grep:
```shell
top
netstat
ps aux
```

Si aparece filtrado, quiere decir que el servicio está listo. Ahora solo nos queda abrir Burpsuite (nuestro proxy de confianza) y hacer lo siguiente:

### pasos e imágenes de configuración del sock

# Ver paquetes con tshark o wireshark




Espero os sirva y que puedas fuzzear a muerte sin ser detectado ;)
¡Experimenta!