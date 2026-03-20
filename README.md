# ChallengeSistecredito
## Comandos para la ejecución del proyecto

# Clonar el proyecto en mi pc:
Para este caso se debe:
1.  Abrir una consola (click derecho en la carpeta en la que quiero que quede ubicado mi proyecto)/Mostrar mas opciones/Open Git Bash here 
2. Digitar el siguiente comaando: git clone (dirección del repo en Git)

NOTA: La dirección del repositorio se toma de la siguiente manera: 
Buscar la opción CODE/Https (En color verde) en el git y copia la URL que allí aparece

## Guardar información de todo lo que voy haciendo 
Utilizar el comando Ctrl s

## Para saber el estado de mi repositorio
git Status

## Para adicionar cambios
git add . 

NOTA: El punto es si quiero que se adicionen todos los archivos sin distención. Sin embargo, si requiero subir un archivo especifico lo especifico de la siguiente manera: git add Readme

## Para dejar un mensaje que indique el cambio que se hizo
git commit -m "xxx"

## cuando tengo un cambio y lo voy a guardar
git push origin main

# Documentación sobre lo que hice:
Construi una API en FastAPI para analizar vectores CVSS v3.1 y devolver un resultado enriquecido: score base, severidad, impacto, explotabilidad, detalle de métricas, descripción del riesgo y recomendaciones de mitigación. Eso se ve en la creación de la app y en el caso de uso principal AnalyzeVectorUseCase



# CVSS v3.1 Analyzer API

Mini plataforma de Quality Engineering enfocada en seguridad, desarrollada en Python con FastAPI, que permite analizar vectores **CVSS v3.1** y devolver un resultado estructurado con:

- Base Score
- Severidad
- Impact Score
- Exploitability Score
- Desglose de métricas
- Descripción del riesgo
- Recomendaciones de mitigación

La solución fue construida como un MVP reutilizable, con una arquitectura modular pensada para evolucionar hacia una capacidad interna de plataforma para equipos de ingeniería, seguridad y calidad. La aplicación se define como una API llamada **“CVSS v3.1 Analyzer API”** y expone análisis de vectores CVSS con resultados enriquecidos. :contentReference[oaicite:1]{index=1}

---
## Objetivo

Automatizar y estandarizar la interpretación de vectores CVSS v3.1, transformando una entrada técnica en una salida más útil y accionable para los equipos que gestionan vulnerabilidades.

Esta herramienta busca reducir la interpretación manual del vector y facilitar la priorización inicial del riesgo mediante una respuesta estructurada. El caso de uso central construye precisamente esa salida a partir del vector, el cálculo del score, la severidad y los servicios de descripción y mitigación. :contentReference[oaicite:2]{index=2}

---
## Alcance de la solución

La API permite:

1. Recibir un vector CVSS v3.1.
2. Validar y procesar la entrada.
3. Calcular el score base, impacto y explotabilidad.
4. Determinar la severidad.
5. Generar un desglose de métricas.
6. Construir una descripción del riesgo.
7. Sugerir mitigaciones.

La solución expone dos endpoints de análisis, uno por `POST` y otro por `GET`, además de un endpoint de salud. :contentReference[oaicite:3]{index=3}

---
