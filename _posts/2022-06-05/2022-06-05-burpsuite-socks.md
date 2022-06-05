---
title: Socks y BurpSuite
author: rabb1t
date: 2022-06-04
categories: [BurpSuite, Socks, tor]
tags: [Anonimato, systemctl, IP, foxyproxy, nmap]
math: true
mermaid: true
image:
  path: /assets/favicon/burpsuite.png
  width: 100
  height: 100
---

## Índice
- [Herramientas que debemos instalar o tener](#herramientas-que-debemos-instalar-o-tener)
- [Configurando BurpSuite](#configurando-burpsuite)
- [Habilitar el servicio tor](#habilitar-el-servicio-tor)
- [Hasta el próximo post](#hasta-el-próximo-post)


El día de hoy, y como primer artículo haremos algo sencillo: aprenderemos a interceptar y enviar peticiones de una forma un tanto diferente a lo habitual ¿Por qué diferente? Pues bien, vamos a usar tor como proxy de BurpSuite. Sí, será un proxy que interceptará datos provenientes de otro proxy, se estarán pasando los ```paquetitos``` como una cadena ¿A poco no suena fascinante? Esto lo haremos con la intención de anonimizar peticiones que enviaremos y recibiremos al hacer pruebas desde el favorito de muchos (por no decir de todos) *'BurpSuite'*.

> No seré de aquellos que te digan qué es un __proxy__, una petición o __tor__ (por lo menos no en un artículo dirigido a un tema en específico como este) para ello tienes diverso material en internet, aunque si quieres que lo explique en un artículo, házmelo saber y sin rechistar lo haré lo más ameno y pronto posible.
{: .prompt-info }

Pero bien, seguro que has venido para configurar esto y ser un poco más sigiloso o anónimo (lo que muchos quisieramos) antes que leer algo denso así que vayamos al asunto:

### Herramientas que debemos instalar o tener:
- tor
- BurpSuite Community o Professional

### Configurando BurpSuite
Cuando tengamos las herramientas instaladas procedemos a abrir BurpSuite, una vez abierto nos dirigimos a la pestaña __User options__. después damos click en __Connections__. Hacemos scroll hacia abajo hasta llegar a las últimas opciones:
![Socks Burpsuite](/assets/favicon/2022-06-04/burpsocks1.png)

Podemos ver el apartado __SOCKS Proxy__. Procedemos a habilitar las opciones: __Use SOCKS proxy__ y __Do DNS lookups over SOCKS proxy__, después digitamos el host y el puerto por el que estará el proxy. Tengamos en cuenta que el puerto de servicio por default de tor estará activo en `9050`:
![Socks Burpsuite](/assets/favicon/2022-06-04/burpsocks2.png)

Una vez hecho lo anterior, para ver que el proxy en BurpSuite fue configurado, pinchamos en la pestaña __Dashboard__ para ver los logs. En Message aparace un log (en mi caso 1, porque ya te digo que eliminé los demás logs) si te aparece el mensaje que te muestro abajo, ya quedó configurado BurpSuite para recibir y enviar las peticiones con el proxy tor:
![Socks Burpsuite](/assets/favicon/2022-06-04/burpsocks3.png)

### Habilitar el servicio tor
Para habilitar el servicio tor escribimos los siguientes comandos en la terminal:

```shell
sudo systemctl start tor
```
{: .nolineno }

En mi caso, salió una ventana para escribir la contraseña de superusuario.
![terminal systemctl star tor](/assets/favicon/2022-06-04/burpsocks4.png)

Podemos verificar que tor fue habilitado usando nmap, como muestro a continuación. Aparece el puerto 9050 abierto, además del puerto por el que escucha BurpSuite `8080`:
![verificar el servicio tor](/assets/favicon/2022-06-04/burpsocks5.png)

También podemos verificarlo con los siguiente comandos:
```shell
systemctl status tor
top
netstat | grep --color "tor"
ps aux | grep --color "tor"
```

Si aparece filtrado, quiere decir que el servicio está listo. Ahora solo nos queda enviar una petición con BurpSuite (nuestro proxy de confianza) pero antes debemos interceptarla desde el navegador:
Para ello he abierto firefox, y me he dirigido a la siguiente url <https://www.cual-es-mi-ip.net/> al entrar en la página se muestra mi dirección IP pública (por razones obvias no lo mostraré, ni censurado :P ). Una vez estando en la página, interceptamos todas las solicitudes que hace el navegador por BurpSuite, gracias a foxyproxy (un addon de firefox) que nos ayuda a dirigir el flujo de peticiones a BurpSuite (os digo que yo ya lo tengo configurado, y es algo que puedes ver en otro post, por lo que no lo explicaré aquí).

> Algo que se me olvidó decir es que debemos tener activada la opción de proxy en BurpSuite para recibir el tráfico.
{: .prompt-info }

Una vez BurpSuite esté preparado para recibir peticiones y foxyproxy esté activado para dirigir el flujo, recargamos la página.

![petición de mi ip](/assets/favicon/2022-06-04/burpsocks6.png)
Vamos a ver la solicitud en BuspSuite, tenemos la solicitud a espera de que hagamos algo con ella. Ahora solamente pinchamos la opción __forward__ varias veces.

Cuando deje de aparecer información de las solicitudes nos dirigimos al navegador a ver lo que ha sucedido:
![tor en acción](/assets/favicon/2022-06-04/burpsocks7.png)
Vemos que la IP ha cambiado, esto quiere decir que el tráfico que hemos enviado de BurpSuite al navegador ha pasado antes por el proxy tor ¡Fantástico!

### Hasta el próximo post
Espero que os sirva, aunque es sencillo, me parece algo interesante para compartir.
Solamente soy un entusiasta de ciberseguridad, si me he equivocado en algo o hay algún aporte hazmelo saber, así aprendemos todos ;)

¡Happy hacking!