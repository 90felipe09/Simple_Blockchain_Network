# Simple Blockchain Network

## Projeto de Redes de Computadores I - PCS 3614

## Autoria:
- Felipe Kenzo Shiraishi - 90felipe09
- Tiago Santa Maria R. Marto - tiagomarto

# Sobre:
O projeto a ser entregue se trata de uma rede de blockchain que possibilite a imutabilidade de uma informação no tempo de forma distribuída.

Para a implementação desta rede, adota-se uma topologia de rede com 3 tipos distintos de nós. Dois deles atuam como clientes enquanto o terceiro atua como servidor ao qual cada um desses dois tipos de cliente se conectam.  A conexão estabelecida entre esses nós será uma conexão TCP/IP utilizando um protocolo de camada de aplicação criado especificamente para esta aplicação à qual denominaremos SBP - Simple Blockchain Protocol.

Estes 3 nós da rede serão denominados Usuário, Minerador e Livro para fins de distinção e identificação. O elemento central transmitido e interpretado nesta rede são artefatos denominados Blocos. Cada bloco representa uma informação que um nó Usuário gostaria de consolidar imutável nesta rede. Assim, o cliente deve ser capaz de gerar requisições por meio de SBP ao nó Livro.

Para fins de identificação de autoria, uma aplicação Usuário deve ser também capaz de gerar chaves públicas e privadas para fins de criptografia assimétrica de chave pública. Além disso, é de interesse para este Usuário consultar o histórico de todas as transações de bloco já feitas e consolidadas pela rede.

![fig. 1: Esquemático da aplicação e da topologia de rede](https://raw.githubusercontent.com/username/projectname/branch/path/to/img.png)


   Para que isso seja possível, o servidor Livro desta rede deve ser capaz de retornar ao Usuário as transações de sua autoria ou armazenar uma requisição de transação para deixar disponível para a rede inteira verificar a sua integridade e se é permitida esta transação de informação.
    
   Então, o nó cliente de um Minerador deve ser capaz de comunicar com o nó servidor Livro para obter este bloco e validar a sua integridade para compor o histórico de transações do livro desta rede. Para isso, realiza-se um processo de custo computacional difícil a fim de dificultar mutações e fraudes no histórico desta rede. Depois, ele deve ser capaz de enviar isso ao Livro, que então irá validar o processamento realizado e consolidar a presença daquele bloco na história do Livro desta rede.
    
   Para delimitar o escopo de aplicação desta rede, os blocos de informação processados representarão transações realizadas com uma moeda virtual arbitrária existente dentro desta rede. É com essa moeda que haverá um incentivo para os nós Mineradores fornecerem suas máquinas para validar a integridade das transações na rede.
    
# Especificação do SBP
   Para implementar este protocolo de camada de aplicação, deve-se entender que tipos de mensagem deseja-se que sejam transmitidas pela rede: blocos a validar (de origem de Usuário e Livro), número validador de bloco (Resolução do Minerador), Hash de bloco anterior (Oriundo de Livro) e Histórico de Blocos (Oriundo de Livro).
   
   Para esses usos, agrupa-se alguns destes dados em declarações no protocolo chamadas de método, especifica-se por um campo/cabeçalho deste protocolo.
   
## Método SEND: Um método utilizado pelo nó Usuário ao enviar um bloco para o Livro.

![fig. 2: Descrição do Método SEND na SBP](https://raw.githubusercontent.com/username/projectname/branch/path/to/img.png)

## Método FETCH: Um método utilizado pelo Minerador para obter um bloco do livro e o hash do último bloco calculado nesta rede.

Além disso, o servidor envia  uma chave pública para o nó minerador criptografar valores calculados para garantir a securidade da informação.

![fig. 3: Descrição do Método FETCH na SBP](https://raw.githubusercontent.com/username/projectname/branch/path/to/img.png)

## Método LIST: Um método utilizado pelo nó Usuário ao enviar ao Livro uma requisição para listar todos os blocos transacionados.

No entanto, listar uma quantidade muito grande blocos pode não caber em um único pacote. Por isso adiciona-se na resposta um atributo indicador de fragmentação “frag_flag” que é 1 quando há pacotes para vir e 0 quando se trata do último pacote.

![fig. 4: Descrição do Método LIST na SBP](https://raw.githubusercontent.com/username/projectname/branch/path/to/img.png)

## Método SOLVE: Um método utilizado pelo Minerador ao Livro para transmitir o número que resolve o bloco obtido.

![fig. 5: Descrição do Método SOLVE na SBP](https://raw.githubusercontent.com/username/projectname/branch/path/to/img.png)

