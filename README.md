# trabalho4

Authenticação de cliente por certificado digital.

- Faz a validação da validade e confiança do certificado.

- Verifica se o certificado foi revogado por OCSP.

Configuração:
- Um certificado digital de um domínio e sua cadeia de custódia no formato PEM dentro da pasta 'siteCerts' com o nome 'fullchain.pem'.
- A chave privado do certificado no formato PEM dentro da pasta 'siteCerts' com o nome 'privkey.pem'.
- No minimo um certificado de uma CA Root no formato PEM dentro da pasta 'CAroot'.


## Demo
![Alt text](demo.gif)