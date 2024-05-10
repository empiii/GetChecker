## Extensão do Burp Suite: GET Checker

### Descrição
Get checker é uma extensão criada para o Burp Suite e detecta possíveis vulnerabilidades de HTTP Verb Tampering. A extensão intercepta requisições POST e as envia como requisições GET para verificar se o servidor responde com status da Fámilia 2XX, indicando que o servidor aceita tanto requisições POST quanto GET para o mesmo recurso.

### Instalação
1. Baixe o arquivo `GETChecker.py`.
2. No Burp Suite, vá para a aba Extender.
3. Clique no botão "Add" e selecione "Python" como tipo de extensão.
4. Selecione o arquivo `GETChecker.py` e clique em "Next".
5. A extensão deve estar carregada e pronta para ser usada.

### Uso
1. Inicie o Burp Suite e certifique-se de que a extensão está carregada.
2. Envie uma requisição POST para uma aplicação alvo.
3. A extensão interceptará a requisição e a enviará como uma requisição GET.
4. Se o servidor responder com um código de status 2XX, um problema será criado indicando possíveis HTTP Verb Tampering.

**Observação:** Para testar a extensão, é necessário ter um servidor web local ou online. Recomendamos o uso do servidor web de teste `Servidorweb.py`, que pode ser executado localmente na porta 8000 com o payload `curl -X POST -x 127.0.0.1:8080 http://localhost:8000 --data 'param1=value1&param2=value2'`.

### Aviso
Esta extensão é fornecida como está e não garante detectar todas as instâncias de HTTP Verb Tampering apenas de `POST` para `GET`. 

# PoC

https://github.com/empiii/GetChecker/assets/47393806/5ed0ebcb-2dbd-4098-a2f5-291c45c07146

