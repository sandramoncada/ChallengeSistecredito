# ChallengeSistecredito
## Comandos para la ejecución del proyecto

---
# Clonar el proyecto en mi pc:
Para este caso se debe:
1.  Abrir una consola (click derecho en la carpeta en la que quiero que quede ubicado mi proyecto)/Mostrar mas opciones/Open Git Bash here 
2. Digitar el siguiente comaando: git clone (dirección del repo en Git)

NOTA: La dirección del repositorio se toma de la siguiente manera: 
Buscar la opción CODE/Https (En color verde) en el git y copia la URL que allí aparece

---

## Guardar información de todo lo que voy haciendo 
Utilizar el comando Ctrl s

---
## Para saber el estado de mi repositorio
git Status

---
## Para adicionar cambios
git add . 

---

NOTA: El punto es si quiero que se adicionen todos los archivos sin distención. Sin embargo, si requiero subir un archivo especifico lo especifico de la siguiente manera: git add Readme

## Para dejar un mensaje que indique el cambio que se hizo
git commit -m "xxx"

---
## cuando tengo un cambio y lo voy a guardar
git push origin main

---

# Challenge Sistecrédito – API de análisis de vulnerabilidades CVSS

## 1. Descripción del proyecto

Este proyecto implementa una API que permite analizar vectores de vulnerabilidad basados en el estándar **CVSS (Common Vulnerability Scoring System)** y generar un análisis estructurado del riesgo.

La solución está diseñada siguiendo principios de **Arquitectura Limpia (Clean Architecture)** y **Domain Driven Design**, separando claramente la lógica del dominio, los casos de uso de la aplicación y la capa de infraestructura que expone la API.

Esto permite que el sistema sea:

- fácil de mantener
- fácil de escalar
- fácil de extender con nuevos análisis de seguridad

---

# 2. Problema que resuelve

En el análisis de vulnerabilidades es importante entender:

- qué tan crítica es una vulnerabilidad
- cómo se calcula su severidad
- qué impacto puede tener
- qué acciones de mitigación se pueden aplicar

Este sistema permite recibir un **vector CVSS**, calcular su score y generar una interpretación del riesgo de seguridad.

---

# 3. Arquitectura de la solución

El proyecto está organizado siguiendo una arquitectura en capas.

```
src
│
├── application
├── domain
└── infrastructure
```

Cada capa tiene una responsabilidad específica.

---

# 4. Capa Domain (Dominio)

La capa de dominio contiene la lógica de negocio central del sistema.

Aquí se definen los conceptos fundamentales del modelo de seguridad basado en CVSS.

```
domain
│
├── entities
│   ├── cvss_vector.py
│   └── cvss_result.py
│
├── services
│   └── cvss_calculator.py
│
└── value_objects
    ├── metrics.py
    ├── severity.py
    └── score.py
```

### Responsabilidades

- representar el modelo de vulnerabilidad CVSS
- calcular el score de una vulnerabilidad
- clasificar el nivel de severidad

El dominio **no depende de ninguna otra capa**.

---

# 5. Capa Application

La capa de aplicación coordina los **casos de uso del sistema**.

Aquí se define cómo interactúan los componentes del dominio para resolver una solicitud del usuario.

```
application
│
├── dtos
│   ├── analysis_request.py
│   └── analysis_response.py
│
├── services
│   ├── description_service.py
│   └── mitigation_service.py
│
└── use_cases
    └── analyze_vector.py
```

### Responsabilidades

- recibir los datos de entrada
- ejecutar el caso de uso de análisis
- coordinar los servicios necesarios
- construir la respuesta para el usuario

---

# 6. Capa Infrastructure

La capa de infraestructura expone el sistema al exterior.

En este proyecto se implementa una **API REST** utilizando **:contentReference[oaicite:2]{index=2}**.

```
infrastructure
│
└── api
    ├── routes
    │   ├── cvss.py
    │   └── health.py
    │
    ├── schemas
    │   ├── requests.py
    │   └── responses.py
    │
    ├── dependencies.py
    └── app.py
```

### Responsabilidades

- definir los endpoints HTTP
- validar requests
- convertir requests en objetos de aplicación
- devolver respuestas HTTP

---

# 7. Flujo de funcionamiento

El flujo del sistema es el siguiente:

1. Un cliente envía una solicitud HTTP a la API.
2. La capa de infraestructura recibe el request.
3. Se construye un objeto de solicitud.
4. Se ejecuta el caso de uso `analyze_vector`.
5. El caso de uso utiliza el dominio para calcular el score CVSS.
6. Se generan descripciones y recomendaciones.
7. Se construye la respuesta final.

---

# 8. Estructura del repositorio

```
ChallengeSistecredito
│
├── src
│   ├── application
│   ├── domain
│   └── infrastructure
│
├── main.py
├── requirements.txt
└── README.md
```
# Repositorio con el código

La solución se entrega en un repositorio Git público que contiene el código fuente completo del challenge, organizado por capas siguiendo principios de arquitectura limpia.

El repositorio incluye:

1. La capa de domain, donde está la lógica central del negocio

2. La capa de application, donde están los casos de uso y servicios de aplicación

3. La capa de infrastructure, donde se expone la API REST

4. El archivo principal de arranque de la aplicación

5. El archivo de dependencias

6. la documentación en el README.md


---

# 9. Instalación y ejecución

## Clonar el repositorio

```
git clone https://github.com/sandramoncada/ChallengeSistecredito.git
cd ChallengeSistecredito
```

---

## Crear entorno virtual

Windows

```
python -m venv venv
venv\Scripts\activate
```

Mac/Linux

```
python3 -m venv venv
source venv/bin/activate
```

---

## Instalar dependencias

```
pip install -r requirements.txt
```

---

## Ejecutar la API

```
uvicorn main:app --reload
```

La API estará disponible en:

```
http://127.0.0.1:8000

Se debe adicionar el vector en el POST: Ejm: {
  "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N"
}
Se debe ejecutar la API con los siguientes comandos en Visual (Run/Terminal/New Terminal)

Pasos para correr en python:
py -m venv venv  - Crea el entorno
en una command prompt - venv\Scripts\Activate.bat
pip install -r requirements.txt - Instalar las librerias
py -m uvicorn main:app --reload - ejecutar

```

Documentación interactiva:

```
http://127.0.0.1:8000/docs
```

---

# 10. Ejemplo de solicitud

```
POST /cvss/analyze
```

```
{
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
}
```

---

# 11. Ejemplo de respuesta

```
{
  "score": 9.8,
  "severity": "Critical",
  "description": "Vulnerabilidad crítica explotable remotamente",
  "mitigation": "Aplicar parches de seguridad y controles de acceso"
}
```

---

# 12. Conclusión

Esta solución demuestra cómo implementar una API de análisis de vulnerabilidades utilizando principios de **Arquitectura Limpia**, separando el dominio, los casos de uso y la infraestructura.

Este enfoque permite mantener el sistema desacoplado y facilita su evolución hacia nuevas capacidades de análisis de seguridad.