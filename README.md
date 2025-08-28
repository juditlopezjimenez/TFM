# Análisis técnico de infraestructuras .onion vinculadas a RaaS y APTs

Este repositorio contiene los **scripts desarrollados en el Trabajo de Fin de Máster (TFM)** de Judit López Jiménez, centrado en el análisis de dominios `.onion` relacionados con campañas de **ransomware** y **Ransomware-as-a-Service (RaaS)** en la Dark Web.

El objetivo es estudiar **patrones técnicos**, detectar **errores de configuración** y explorar **posibles vínculos entre servicios ocultos y grupos APT**.

## Contenido del repositorio

- `fingerprinting.py` → extracción y análisis de **cabeceras HTTP** para generar huellas digitales y detectar configuraciones comunes.  
- `favicon.py` → descarga y análisis de **favicons**, calculando hashes (MD5 y Murmur3) para identificar reutilización en distintos servicios.  
- `tls_extract.py` → extracción de **certificados TLS** de servicios `.onion` a través de Tor, útil para correlación e identificación de infraestructura.  

## Requisitos

- **Sistema operativo**: Linux o macOS (recomendado usar VM dedicada).  
- **Dependencias**:
  - Python 3.9+  
  - Librerías: `requests`, `cryptography`, `hashlib`, `base64`, `argparse`, `json`  
  - Cliente Tor activo (`tor` en ejecución en `127.0.0.1:9050`)  
- **Herramientas externas**:  
  - [GoWitness](https://github.com/sensepost/gowitness) → capturas de pantalla de sitios .onion  
  - [ProjectDiscovery tools](https://projectdiscovery.io/) (`httpx`, `nuclei`)  

## Ejemplo de uso

### Análisis de cabeceras HTTP

python3 fingerprinting.py -i resultados-array.json -o fingerprints.csv
