# Análise dos resultados — AES-GCM em IoT: segurança após reinícios

Análise realizada em **22/11/2026**, com base no relatório parcial **“AES-GCM em IoT: segurança após reinícios”**, fornecido no arquivo `Trabalho final - Segurança (2).pdf`, nas implementações de emissor, receptor e controlador, e nos quatro CSVs da execução completa. O objetivo é fornecer uma base verificável para a seção de resultados e discussão do trabalho.

Fontes de implementação: [campanhas e procedimentos](../iot/campaigns.py), [coleta de eventos e métricas](../iot/harness.py), [emissor](../iot/emitter.py), [receptor](../iot/receiver.py) e [criptografia e persistência](../iot/common.py). O PDF fornecido tem 21 páginas e SHA-256 `115bc93dc2f11b9fe1929b90fc5af0f44a094aa6f24c116cf1a241e27c0563bb`; as páginas citadas usam a ordem física do PDF.

**Conclusão principal:** os resultados sustentam, no ambiente e nas falhas exercitadas, a hipótese de que a reserva antecipada reduz as atualizações persistentes do emissor preservando a unicidade dos nonces. Também mostram que a proteção contra replay depende separadamente do estado do receptor. Há, entretanto, diferenças entre algumas métricas implementadas e as definições do projeto, especialmente em **F2 e F5**; elas são explicitadas abaixo e devem acompanhar a redação dos resultados.

## 1. Relação com as hipóteses do projeto

A hipótese principal aparece na seção 5 do relatório parcial, p. 18 do PDF. A tabela desdobra essa hipótese e os critérios das seções 3, 4.4 e 5.2 em questões de análise; os rótulos abaixo são organizadores deste README, não hipóteses numeradas originalmente no projeto.

| Questão | Evidência encontrada | Avaliação permitida |
|---|---|---|
| A reserva antecipada reduz transações sem reutilizar nonces? | C2 fez 63, 16 e 4 transações do emissor por 1.000 cifragens contínuas, contra 1.000 em C1; nenhuma reutilização nas configurações protegidas | Hipótese sustentada nos cenários observados |
| Persistir antes de cifrar permite recuperar o emissor após F1–F3? | C1/C2 apresentaram zero reutilizações, entrega de todas as amostras e recuperação em até 10 s nos 390 ensaios de falha do emissor | Critério atendido nos ensaios; custo de F2 exige ressalva de instrumentação |
| A perda do histórico do receptor permite replay mesmo com emissor protegido? | Emissor C1 em todos os ensaios: histórico volátil aceitou 1.200/1.200 replays; persistente aceitou 0/2.400 | Distinção entre unicidade de nonce e proteção contra replay demonstrada |
| Blocos maiores trocam menos gravações por mais sequências descartadas? | F3 na primeira cifragem de um bloco descartou 15, 63 e 255 valores em C2; as transações contínuas caíram com B | Compromisso observado; os instantes 250/500/750 não distinguem todos os tamanhos de bloco |
| Persistir a aceitação antes da entrega impede duplicação, mas pode perder uma entrega? | F5 apresentou 999 eventos de entrega por 1.000 amostras, uma rejeição adicional por replay e nenhuma duplicata entregue | Resultado compatível com o mecanismo; falta a verificação independente do estado persistente exigida pelo projeto |

Zero violações nestes testes não é prova geral de segurança. A contagem de transações também não mede diretamente desgaste de flash, energia ou tempo de escrita física.

## 2. Dados utilizados e verificação de completude

| Arquivo de origem | Combinações de cenário | Repetições por cenário | Execuções | Cifragens registradas |
|---|---:|---:|---:|---:|
| [continuous.csv](../results/continuous.csv) | 5 | 10 | 50 | 50.000 |
| [emitter_restart.csv](../results/emitter_restart.csv) | 15 | 10 | 150 | 150.000 |
| [directed.csv](../results/directed.csv) | 29 | 10 | 290 | 22.440 |
| [receiver_restart.csv](../results/receiver_restart.csv) | 18 | 10 | 180 | 180.000 |
| **Total** | **67** | **10** | **670** | **402.440** |

Foram verificadas as identidades de todos os cenários esperados, as dez repetições `run=0…9`, a ausência de linhas duplicadas e os totais de amostras. Todas as 440 execuções de falha do emissor, somando `emitter_restart` e `directed`, registram `crashed=True`. Cada execução da terceira campanha reapresentou 20 quadros, e os 20 chegaram ao procedimento de recepção contabilizado.

A campanha `integrity` é adicional e não integra essas 670 linhas. O [log da retomada](../results/resume.log) registra **13/13 verificações aprovadas**. Na análise, também foram reexecutados os sete testes de [test_crypto.py](../tests/test_crypto.py), todos aprovados; esse resultado é uma verificação atual, não um novo dado das campanhas históricas.

Não foram misturados os arquivos de `results/quick`, os testes curtos de manutenção ou resultados da execução interrompida sem CSV. `continuous` e `emitter_restart` foram preservados da primeira execução; seus hashes continuam iguais aos do backup anterior à retomada. `directed` foi refeita integralmente porque a implementação antiga não salvava seus resultados intermediários, e `receiver_restart` foi executada em seguida. Os CSVs indicam conclusões em 19 e 20/11/2026 por suas datas de modificação; essas datas não substituem registros temporais por execução.

Os 670 registros representam ensaios independentes, com novo provisionamento a cada ensaio. A soma de cifragens não representa o uso de uma única chave por 402.440 mensagens.

## 3. O que foi efetivamente simulado

### 3.1 Ambiente, comunicação e estado

A implementação executa **processos reais em software**, com comunicação MQTT local e bancos SQLite reais. Não é uma simulação de rede por eventos discretos nem uma emulação do desempenho de ESP32 ou Raspberry Pi.

| Elemento | Configuração efetiva |
|---|---|
| Pontas | Um emissor e um receptor Python por ensaio; contexto `dev-1` / `k1` |
| Broker | Mosquitto próprio por ensaio, em porta local disponível; não reiniciado durante as falhas das pontas |
| Transporte | MQTT 3.1.1, QoS 1, sem mensagens retidas, endereço `127.0.0.1` |
| Sessão do receptor | Identificador fixo e `clean_session=False`, permitindo reentrega após reconexão |
| Persistência do broker | Desativada em disco; fila configurada sem limite de mensagens; processo permanece ativo |
| Criptografia | AES-256-GCM via PyCryptodome; nonce de 96 bits; tag de 128 bits |
| Nonce | Prefixo aleatório de 64 bits provisionado no ensaio, concatenado com sequência de 32 bits em ordem de rede |
| Chave | Aleatória, 256 bits, nova a cada ensaio e mantida nos reinícios desse ensaio |
| AAD | JSON UTF-8 com ordem fixa de `v`, `dev`, `kid`, `seq`, sem espaços opcionais |
| Quadro | JSON com cabeçalho, nonce, texto cifrado e tag; campos binários em Base64 |
| Conteúdo | Telemetria sintética com identificador de amostra, instante, temperatura e umidade, preenchida até 128 bytes antes da cifragem |
| Cadência | **Nominal de 10 mensagens/s**; pausas e recuperação fazem parte dos cenários de falha |
| Estado persistente | Bancos SQLite independentes; `journal_mode=WAL`, `synchronous=FULL`, transações explícitas |
| Receptor persistente | Aceita quadro autenticado somente se `seq > h`; confirma a atualização de `h` antes do evento de entrega |
| Amostras | Identificador lógico separado da sequência criptográfica: permite reconhecer uma amostra nova mesmo quando C0 reutiliza a sequência |

O broker não recebe a chave pela aplicação. Isso descreve a separação lógica de responsabilidades; os processos locais não constituem um experimento de isolamento contra um administrador da máquina.

A sequência é reiniciada em zero apenas no controle inseguro C0. C1 recupera o limite exclusivo persistido e reserva um valor antes de cada cifragem. C2 faz o mesmo com blocos de **B=16, 64 ou 256**. O restante de uma reserva anterior não é reutilizado após o reinício. No código há verificação de esgotamento do contador de 32 bits, mas estas campanhas não chegam perto desse limite e não o validam experimentalmente.

### 3.2 Pontos de falha

| Ponto | Local da interrupção | O que pode ter sido confirmado |
|---|---|---|
| F1 | Antes da transação que reserva sequências | A reserva anterior; a nova ainda não foi gravada |
| F2 | Depois do `COMMIT` da reserva, antes de cifrar usando-a | Um bloco novo inteiro, ainda não usado |
| F3 | Depois da cifragem e do registro `encrypted`, antes da publicação | A reserva e a evidência de que o nonce já foi usado |
| F4 | Depois da autenticação e do teste de sequência, antes de persistir `h` | Ainda não há confirmação dessa aceitação |
| F5 | Depois do `COMMIT` de `h`, antes do registro `accepted` e da entrega | Aceitação persistente, mas sem evento de entrega |

F1–F5 encerram o processo por `os._exit(99)`, sem limpeza normal. A falha ordinária do receptor usa `SIGKILL`. Os arquivos de estado são preservados e o controlador cria novos processos sobre eles. Não foram injetados cortes físicos de energia, falhas internas durante o `COMMIT`, corrupção aleatória de páginas ou rollback malicioso.

### 3.3 Campanha 1: operação contínua

Cinco configurações × dez repetições × 1.000 amostras. O receptor mantém histórico persistente em todas. A ordem das configurações é rotacionada entre repetições **nesta campanha**. Não há interrupção nem reapresentação deliberada de quadros.

### 3.4 Campanha 2: reinícios do emissor

Cinco configurações × três posições de falha × dez repetições: **150 execuções**. Cada execução produz 1.000 amostras e contém **uma única falha F3**, após a 250ª, 500ª ou 750ª cifragem. Não são três reinícios na mesma execução.

O receptor continua ativo e persistente. O controlador publica o quadro que já havia sido cifrado, mas ainda não publicado, e reinicia o emissor na próxima amostra lógica. Essa reapresentação não é uma nova cifragem. Assim, a entrega completa de C1/C2 inclui essa intervenção do controlador; não demonstra recuperação autônoma de um buffer de saída durável implementado no emissor.

### 3.5 Complemento dirigido da campanha 2

Os testes dirigidos contêm dez repetições por caso, com uma falha por execução:

| Configuração | Casos | Execuções |
|---|---|---:|
| C0 | F3 nas ocorrências 1 e 2 | 20 |
| C1 | F1, F2 e F3, cada um nas ocorrências 1 e 2 | 60 |
| C2-16 | F1/F2 nas reservas 1 e 2; F3 nas cifragens 1, 16 e 17 | 70 |
| C2-64 | F1/F2 nas reservas 1 e 2; F3 nas cifragens 1, 64 e 65 | 70 |
| C2-256 | F1/F2 nas reservas 1 e 2; F3 nas cifragens 1, 256 e 257 | 70 |

`occurrence` conta visitas ao ponto de falha, e não sempre mensagens: em F1/F2 conta **reservas**; em F3 conta **cifragens**.

Esses ensaios **não têm todos 1.000 amostras**. O total é `min(1000, E + 30)`, com `E=n` em F3 e `E=(n−1)B+1` em F1/F2. Os totais variam de **31 a 287**. Por exemplo, F2 na segunda reserva de C2-64 produz 95 amostras no ensaio completo; F3 na 256ª cifragem de C2-256 produz 286. Os limites escolhidos permitem explorar a primeira reserva e a passagem para a segunda.

### 3.6 Campanha 3: reinícios do receptor e das duas pontas

O emissor usa **C1 em todos os casos**. São seis cenários × três posições (250/500/750) × dez repetições, sempre com 1.000 amostras: **180 execuções**.

| Cenário | Procedimento efetivo |
|---|---|
| `receiver`, volátil ou persistente | Após observar pelo menos k aceitações, o controlador congela o emissor com `SIGSTOP`, encerra o receptor por `SIGKILL`, reinicia-o, injeta replays e libera o emissor com `SIGCONT` |
| `both`, volátil ou persistente | O emissor produz k amostras e **termina normalmente**; depois o receptor é encerrado abruptamente. Ambos são iniciados novamente para continuar o ensaio |
| F4, persistente | O receptor encerra a execução na k-ésima visita a F4; o emissor é congelado durante a recuperação |
| F5, persistente | O receptor encerra a execução na k-ésima visita a F5; o emissor é congelado durante a recuperação |

Em cada caso, são selecionados até 20 quadros com evento de aceitação anterior à falha, espaçados ao longo do conjunto disponível e reapresentados em ordem crescente. Neste conjunto completo, foram sempre 20. Após os replays, há espera de aproximadamente 0,5 s sem novos eventos antes da continuação do emissor.

Portanto, `both` avalia reinicialização das duas pontas, mas **não representa uma queda abrupta simultânea das duas**, prevista no modelo de falhas do relatório. A pausa do emissor também torna a janela de recuperação controlada; não é tráfego contínuo irrestrito enquanto o receptor está indisponível. Como o emissor calcula seus prazos em relação ao início do processo, pode produzir uma rajada ao recuperar o atraso depois de `SIGCONT`; 10 mensagens/s é a cadência nominal, não uma garantia de espaçamento constante após a pausa.

## 4. Como interpretar as métricas e os resumos

| Métrica | Definição efetivamente usada | Cuidado na interpretação |
|---|---|---|
| `encryptions` | Número de eventos `encrypted` | Inclui a cifragem que precede F3, mesmo sem publicação pelo emissor |
| `nonce_reuse` | Cifragens menos pares distintos `(kid, nonce)` dentro do ensaio | Válido aqui porque a chave associada a `kid` não muda no ensaio; não comparar `kid` entre provisionamentos |
| `generated` | Quantidade de identificadores de amostra nos eventos de cifragem | Não é contador de mensagens publicadas; neste conjunto coincide com `encryptions` |
| `accepted_distinct` | Amostras distintas com evento `accepted` | Em F5 mede entregas registradas, não todas as aceitações persistentes do projeto |
| `duplicate_acceptances` | Eventos `accepted` menos amostras distintas nesses eventos | Mostra entrega duplicada, não reutilização de nonce |
| `lost_samples` | Amostras cifradas sem evento de aceitação, classificadas por rejeição observada ou `not_received` | `replay` pode ser uma amostra nova com sequência repetida em C0, ou a reentrega da amostra afetada por F5 |
| `emitter_transactions` | Soma de `persisted` nos eventos `encrypted` | Omite o `COMMIT` seguido imediatamente de F2 |
| `receiver_transactions` | Soma de `persisted` nos eventos `accepted` | Omite o `COMMIT` seguido imediatamente de F5 |
| `discarded_sequences` | Salto entre a última sequência cifrada e a sequência recuperada após reinício | Não contabiliza uma reserva perdida antes da primeira cifragem nem o saldo no fim normal da execução |
| `prep_median_us`, `prep_p95_us` | Mediana e P95 dos tempos de preparação registrados em cada execução | Inclui obtenção da sequência, persistência quando aplicável, construção da telemetria, AES-GCM e serialização; exclui espera de cadência, publicação, ACK e recepção |
| `recovery_s` | Tempo do marcador de reinício no controlador até o primeiro `accepted` de uma amostra posterior à última já cifrada no marcador | Inclui o roteiro do controlador; valor nulo significa ausência de recuperação registrada em até 10 s |
| `replays_accepted / replays_reached` | Aceitações dos replays selecionados divididas pelos eventos de recepção desses quadros | O denominador correto é o que chegou; aqui coincide com o que foi enviado |

A recuperação usa identificadores de amostra, não apenas sequências criptográficas, e exclui a reapresentação do quadro interrompido em F3. Os instantes são atribuídos quando as linhas de evento chegam ao controlador, podendo incluir escalonamento e leitura do pipe.

**Convenção das tabelas:** contagens invariantes são apresentadas uma vez, por execução; tempos são **mediana entre repetições [mínimo–máximo]**. Para preparação, isso significa mediana das dez medianas e mediana dos dez P95. **Não é o P95 do conjunto concatenado de mensagens**, nem um intervalo de confiança. Os tempos individuais por mensagem não foram preservados nos CSVs, portanto não permitem reconstruir a distribuição completa ou o P95 global. O P95 implementado usa o elemento de índice `int(0,95 × N)` em uma lista ordenada, com índice iniciado em zero; pode diferir de outras convenções de percentil, sobretudo nos ensaios curtos.

## 5. Resultados da operação contínua

Todas as configurações registraram, por execução, 1.000 cifragens, 1.000 amostras distintas entregues, zero duplicatas, zero reutilizações de nonce e nenhuma perda. Isso inclui C0: sem reinício, seu contador volátil ainda não retorna a zero.

| Configuração | Transações emissor | Redução frente a C1 | Transações receptor | Mediana de preparação (µs) | P95 de preparação (µs) |
|---|---:|---:|---:|---:|---:|
| C0 | 0 | Não é alternativa segura sob reinício | 1.000 | 226 [185–231] | 234,5 [212–243] |
| C1 | 1.000 | Referência | 1.000 | 251 [240–282] | 301 [281–304] |
| C2-16 | 63 | 93,7% | 1.000 | 221 [185–230] | 263 [239–295] |
| C2-64 | 16 | 98,4% | 1.000 | 218 [186–230] | 235 [229–251] |
| C2-256 | 4 | 99,6% | 1.000 | 196,25 [184–229] | 230,5 [208–235] |

As contagens de C2 coincidem com `ceil(1000/B)`. O ganho é claro na quantidade de transações. As medianas de preparação foram aproximadamente **12,0%, 13,1% e 21,8% menores** que C1 para B=16, 64 e 256, respectivamente, comparando as medianas agregadas da tabela. Não se trata de uma análise pareada por mensagem nem de um teste de significância.

A redução percentual de transações **do emissor** não deve ser atribuída ao sistema inteiro. Somando emissor e receptor, C1 realizou 2.000 transações por execução; C2-16, C2-64 e C2-256 realizaram 1.063, 1.016 e 1.004, reduções de **46,85%, 49,2% e 49,8%**, respectivamente. O receptor continua persistindo por mensagem.

O ganho de latência não acompanha a redução de transações na mesma proporção: continuam existindo custos de Python, AES-GCM, criação do quadro e serialização. Além disso, os intervalos entre repetições se sobrepõem para diferentes configurações. C2-256 apresentou a menor mediana agregada neste conjunto, mas estes dados não estabelecem superioridade universal, vazão máxima ou economia energética.

## 6. Resultados dos reinícios do emissor

### 6.1 Controle C0: reutilização de nonces e perda de amostras novas

Resultados invariantes nas dez repetições de cada posição:

| Falha após k cifragens | Cifragens que reutilizam nonce | Amostras entregues / geradas | Amostras novas rejeitadas como replay | Recuperações em até 10 s |
|---:|---:|---:|---:|---:|
| 250 | 250 | 750/1.000 | 250 | 0/10 |
| 500 | 500 | 500/1.000 | 500 | 0/10 |
| 750 | 250 | 750/1.000 | 250 | 0/10 |

O padrão é `min(k, 1000−k)` reutilizações: depois do reinício, o emissor volta à sequência zero, mas o receptor preserva `h`. As novas amostras que reutilizam sequências antigas passam pela autenticação e são rejeitadas pela regra monotônica. Essa rejeição evita sua entrega, mas não desfaz a reutilização de nonce que já ocorreu no emissor.

Com k=250, o total de 750 amostras entregues mostra que houve retomada da entrega de amostras posteriores ao reinício, mas fora do limite de 10 s. Pela cadência e pelo avanço necessário do contador, espera-se uma espera próxima de 25 s; **esse tempo é uma inferência do mecanismo, não uma medição preservada no CSV**. Com k=500 ou 750, a quantidade restante de amostras não permite superar `h`, e os totais entregues correspondem às amostras anteriores ao reinício, incluindo o quadro F3 reapresentado.

Ao todo, essa campanha contém **10.000 cifragens com reutilização em C0**. Não houve ataque implementado para recuperar chave, texto claro ou forjar tags a partir delas: a violação medida é a repetição do par chave–nonce. C0 é um controle criado para o experimento; estes resultados não demonstram falha no esquema de nonces aleatórios do artigo de referência.

### 6.2 C1 e C2: unicidade, transações e descarte

Nas **120 execuções protegidas** desta campanha, todas as 1.000 amostras foram entregues por execução, sem reutilização de nonce, sem duplicatas e sem perdas. Houve recuperação dentro de 10 s em **120/120** casos.

| Configuração | k=250: transações / descartes | k=500: transações / descartes | k=750: transações / descartes |
|---|---:|---:|---:|
| C1 | 1.000 / 0 | 1.000 / 0 | 1.000 / 0 |
| C2-16 | 63 / 6 | 64 / 12 | 63 / 2 |
| C2-64 | 16 / 6 | 16 / 12 | 16 / 18 |
| C2-256 | 4 / 6 | 4 / 12 | 4 / 18 |

Cada célula apresenta transações **do emissor** e sequências descartadas no reinício, por execução, invariantes nas dez repetições. O receptor fez 1.000 transações em todos esses casos.

Para uma falha F3 após k cifragens, as contagens se explicam por:

- `D(B,k) = ceil(k/B) × B − k`: saldo da reserva abandonada no reinício;
- `T(B,k,N) = ceil(k/B) + ceil((N−k)/B)`, com `N=1000`: reservas confirmadas nos dois trechos.

C2-16, por exemplo, precisou de uma transação adicional quando k=500. C2-64 e C2-256 apresentaram o mesmo descarte nos três instantes porque 250, 500 e 750 estão a 6, 12 e 18 posições dos respectivos limites de reserva em ambos os casos. **Essa igualdade resulta do alinhamento dos instantes escolhidos; não significa que blocos de 256 tenham o mesmo custo de descarte de blocos de 64 em geral.**

Agrupando as 120 recuperações protegidas, a mediana foi **65,26 ms**, com intervalo **58,43–96,11 ms**. As medianas por configuração e posição variaram entre aproximadamente 63,69 e 66,76 ms. Não há evidência de penalidade relevante de recuperação ao aumentar B dentro deste conjunto; o cálculo não isola os custos de criação do processo, conexão MQTT e armazenamento.

## 7. Resultados dos testes dirigidos e limites de medição em F2

C1/C2 completaram **270 execuções dirigidas**, com **21.810 cifragens**, zero reutilizações, entrega de todas as amostras e recuperação em até 10 s em todos os casos. A mediana agrupada de recuperação foi **65,11 ms [57,96–94,00 ms]**. C0 apresentou uma reutilização e uma perda em F3#1 e duas em F3#2, em cada repetição: **30 reutilizações e 30 perdas** no total. Seus ensaios curtos recuperaram a entrega em até 10 s porque precisavam superar apenas uma ou duas sequências anteriores.

### 7.1 Descarte em fronteiras de reserva

| Política | F3 na primeira cifragem do bloco | F3 no fim da primeira reserva | F3 na primeira cifragem da segunda reserva |
|---|---:|---:|---:|
| C1, B=1 | 0 | 0 | 0 |
| C2-16 | 15 | 0 | 15 |
| C2-64 | 63 | 0 | 63 |
| C2-256 | 255 | 0 | 255 |

São descartes por execução, iguais nas dez repetições. Para C1, primeira cifragem e fim da primeira reserva são o mesmo caso F3#1; a segunda reserva corresponde a F3#2. Esses resultados mostram diretamente o custo de abandonar a parte não usada de uma reserva.

**O limite B−1 vale aqui para F3, depois de pelo menos uma cifragem no bloco. Não é um limite geral para todas as falhas.** Em F2, o processo pode morrer imediatamente depois de reservar e antes de usar qualquer valor, descartando **B valores**, inclusive um valor em C1.

### 7.2 Transações e descartes subcontados em F2

O controlador soma o campo `persisted` de eventos `encrypted`. Em F2, a transação foi confirmada, mas o processo encerrou antes de gerar esse evento. Consequentemente, **cada execução F2 omite uma transação do emissor** no CSV. Há 80 execuções nessa condição.

Além disso, `discarded_sequences` depende de existir uma última cifragem anterior ao reinício. Em F2#1 ainda não existe nenhuma, e o CSV registra zero mesmo que uma reserva inteira tenha sido abandonada. Em F2#2 já existe essa referência, e o salto de B é contabilizado.

| Política | F2#1: transações no CSV → previstas pelo código | F2#2: transações no CSV → previstas pelo código | F2#1: descarte no CSV → previsto pelo código | F2#2: descarte no CSV |
|---|---:|---:|---:|---:|
| C1 | 31 → 32 | 32 → 33 | 0 → 1 | 1 |
| C2-16 | 2 → 3 | 3 → 4 | 0 → 16 | 16 |
| C2-64 | 1 → 2 | 2 → 3 | 0 → 64 | 64 |
| C2-256 | 1 → 2 | 2 → 3 | 0 → 256 | 256 |

Os valores à direita das setas são **inferências determinísticas do fluxo de código e dos pontos de falha**, não novas medições dos bancos históricos. Os dados brutos não foram corrigidos ou substituídos. Uma análise do custo de persistência em F2 deve exibir essa distinção, ou usar uma nova execução instrumentada com eventos independentes de confirmação de transação.

As latências de preparação dos dirigidos também exigem cuidado: alguns casos F3 muito curtos têm medianas dos P95 próximas de 2 ms. Poucas cifragens iniciais podem ocupar parcela relevante de uma execução de 31/32 mensagens, diferentemente de um ensaio de 1.000. A influência da inicialização é uma explicação compatível com o procedimento, mas não pode ser decomposta sem tempos por mensagem. Não se deve misturar os dirigidos à campanha contínua para calcular uma única distribuição de desempenho.

## 8. Resultados dos reinícios do receptor

A tabela agrega as três posições e as dez repetições, totalizando **30 execuções por linha**. A fração usa os replays que chegaram ao procedimento de recepção, conforme o projeto.

| Cenário | Histórico | Replays enviados | Replays recebidos | Replays aceitos | Proporção aceita | Amostras sem entrega por execução | Recuperação, ms: mediana [mín.–máx.] |
|---|---|---:|---:|---:|---:|---:|---:|
| Receptor | Volátil | 600 | 600 | 600 | 100% | 0 | 620,70 [618,38–664,25] |
| Receptor | Persistente | 600 | 600 | 0 | 0% | 0 | 639,36 [618,69–646,49] |
| Ambas as pontas | Volátil | 600 | 600 | 600 | 100% | 0 | 693,70 [677,92–748,62] |
| Ambas as pontas | Persistente | 600 | 600 | 0 | 0% | 0 | 701,82 [676,93–728,18] |
| F4 | Persistente | 600 | 600 | 0 | 0% | 0 | 641,41 [618,62–645,49] |
| F5 | Persistente | 600 | 600 | 0 | 0% | 1 | 641,11 [619,22–661,45] |

Todas as 180 execuções registraram recuperação dentro de 10 s e zero reutilizações de nonce, já que o emissor continuou protegido por C1. A proteção do emissor, isoladamente, não impediu replay: as 60 execuções com histórico volátil registraram 20 aceitações duplicadas cada, somando **1.200**. Já as 120 execuções com histórico persistente rejeitaram os **2.400** replays selecionados.

Os 100% de aceitação do controle volátil são específicos da seleção e da ordem usadas. Os quadros antigos foram reapresentados em ordem crescente, antes da continuação do tráfego novo. Não se deve interpretar essa taxa como probabilidade universal de sucesso de qualquer ataque de replay em qualquer ordenação.

O tempo de recuperação do receptor é maior que o do emissor, mas **não pode ser atribuído diretamente ao custo de recuperar SQLite**: inclui reinício, reconexão, injeção dos 20 replays, espera de aproximadamente 0,5 s e liberação ou recriação do emissor. Os aproximadamente 0,62–0,70 s caracterizam o roteiro experimental completo. Não se deve simplesmente subtrair 0,5 s e apresentar o restante como um tempo de armazenamento medido.

### 8.1 F4: mensagem ainda não persistida

F4 apresentou 1.000 amostras entregues e 1.000 transações registradas no receptor por execução. Os 20 replays selecionados foram rejeitados. O comportamento é compatível com a reentrega pelo MQTT da mensagem interrompida antes da confirmação de `h`, que ainda pode ser aceita após a recuperação. Não houve perda final registrada nesses ensaios.

### 8.2 F5: diferença entre aceitação persistente e entrega

O relatório define aceitação pela confirmação persistente de `h` e exige que F5 seja verificado pelo estado recuperado, não apenas pelo log posterior (seção 4.4, p. 17 do PDF). A implementação do resumo usa o evento `accepted`, emitido **depois de F5**, como referência para aceitação e transações do receptor.

Em cada execução F5, os CSVs mostram:

- 1.000 cifragens e 999 amostras distintas com evento de entrega;
- 999 transações contabilizadas no receptor;
- 20 replays selecionados recebidos e rejeitados;
- 21 rejeições com motivo `replay`: as 20 selecionadas mais uma rejeição associada à amostra que não teve evento de entrega;
- uma amostra em `lost_samples`, classificada como `replay`;
- nenhuma duplicata entregue.

Esse conjunto é **compatível com uma mensagem persistida antes da falha e rejeitada ao ser reentregue, sem entrega à aplicação**. A previsão pelo fluxo implementado é de **1.000 transações confirmadas no receptor**, uma das quais não aparece no contador. As 30 execuções F5 somaram 30 amostras sem evento de entrega, ou 0,1% das 30.000 geradas nesse subconjunto.

Isso não autoriza escrever que “apenas 999 mensagens tiveram aceitação persistente” nem que “o banco confirmou exatamente 999 transações”. Também não comprova, pela via independente prevista no projeto, a recuperação do `h` correspondente ao quadro afetado: o resumo não salva o valor persistido no reinício, e os bancos/eventos completos dos ensaios concluídos foram removidos. Os replays selecionados são quadros com evento anterior de aceitação; **o quadro interrompido em F5 não integra automaticamente essa seleção**.

Para fechar esse requisito, uma validação complementar deveria registrar `h` após reabrir o banco, identificar o quadro interrompido e comprovar sua rejeição específica, separando eventos de `commit`, aceitação persistente e entrega. Esta análise não alterou os resultados históricos nem executou novamente a campanha para preencher essa lacuna.

## 9. Validação funcional e aderência ao relatório parcial

O log de `integrity` registra aprovação de envio legítimo, replay exato, alteração de texto cifrado, tag, cabeçalho e nonce, manutenção do total de entregas e de `h`, além de interrupção diante de estados inválidos/ausentes. Os casos concretos de estado são: limite negativo, registro ausente, arquivo ausente e banco corrompido no emissor; registro ausente no receptor. Não é uma cobertura exaustiva de todas as formas de corrupção de ambas as pontas.

O teste de cabeçalho da campanha altera a sequência sem ajustar o nonce e aceita rejeição por estrutura ou autenticação. Portanto, ele não isola sozinho a ligação criptográfica do AAD; o teste unitário `test_frame_roundtrip_and_aad_binding` verifica diretamente a falha de autenticação ao alterar o AAD.

Os quatro vetores conhecidos em `test_crypto.py` são os casos 13–16 identificados pelo código como vetores da especificação GCM, com AES-256, IV de 96 bits e tag de 128 bits, com e sem AAD. Eles foram aprovados, mas não há registro de execução de uma bateria CAVP nem de download dos vetores mencionados no planejamento. O relatório final deve descrever o conjunto efetivamente utilizado.

| Previsão do relatório | Situação observada e consequência para a redação |
|---|---|
| Comparar C0, C1 e C2 com B=16/64/256 e dez repetições | Executado; cobertura dos CSVs completa |
| Separar segurança do emissor e histórico do receptor | Executado; campanha 3 mantém C1 |
| Medir custo por transações confirmadas | Correspondência adequada em operação contínua/F3; F2 e F5 subcontam commits sem evento posterior |
| Verificar aceitação persistente em F5 pelo estado recuperado | Evidência agregada compatível, mas verificação independente não foi preservada |
| Reinício abrupto de ambas as pontas | O caso `both` termina o emissor normalmente; não cobre queda simultânea abrupta |
| Alternar a ordem das configurações | Implementado em `continuous`; as demais campanhas usam ordem fixa |
| Registrar versões e condições de carga | Os resultados não incluem inventário contemporâneo de hardware, versões e carga por execução; não reconstruir como se tivesse sido medido |
| Registrar cifragens, publicações, recepções e aceitações | Há instrumentação de cifragens/decisões de recepção, mas não uma trilha persistida completa de publicações e recepções brutas; restaram CSVs agregados |
| Integração inicial com nonces aleatórios de 12 bytes | Não há campanha específica salva demonstrando essa etapa; a comparação principal usa prefixo + contador |
| Limitar conclusões a software e falhas representadas | Necessário: não houve teste em hardware IoT, queda de energia, falha do broker, rollback ou múltiplos emissores concorrentes |

Houve mudança de infraestrutura entre os conjuntos preservados e os novos: o controlador passou a fechar explicitamente recursos, aguardar o leitor de eventos e salvar checkpoints. As políticas de nonce e de recepção permaneceram as mesmas. Ainda assim, as campanhas não formam uma única sessão com condições de carga e instrumentação perfeitamente uniformes; comparações finas de tempo devem priorizar cenários da mesma campanha.

Não houve campanha de reordenação deliberada de amostras novas. A regra `seq > h` permite saltos de sequência, mas pode rejeitar quadros legítimos atrasados; a ausência de perdas em C1/C2 nestes ensaios não demonstra tolerância geral a reordenação. Tampouco foram avaliadas várias falhas sucessivas no mesmo provisionamento: cada execução com falha contém um reinício experimental.

## 10. Síntese para a discussão dos resultados

Uma redação possível, a ser adaptada ao artigo:

> Na operação contínua, a reserva antecipada reduziu o número de transações do emissor de 1.000 por execução em C1 para 63, 16 e 4 em C2, para blocos de 16, 64 e 256 valores, respectivamente. Essas reduções de 93,7%, 98,4% e 99,6% foram acompanhadas de menores medianas agregadas de preparação do quadro. O receptor, contudo, manteve uma atualização persistente por mensagem, de modo que o benefício não corresponde à mesma redução percentual no conjunto das duas pontas.
>
> Nos ensaios de reinício do emissor, C1 e C2 não apresentaram reutilização de nonces e entregaram todas as amostras, incluindo o quadro interrompido em F3 reapresentado pelo controlador. O controle C0 reutilizou nonces e ocasionou rejeição de amostras novas pelo receptor persistente. Os testes dirigidos evidenciaram o compromisso da reserva antecipada: reinícios próximos do início de um bloco abandonaram mais sequências, chegando a 255 valores após uma cifragem em C2-256. Falhas imediatamente após a confirmação de uma reserva podem abandonar o bloco inteiro, e a instrumentação de F2 subconta parte desse custo.
>
> A campanha do receptor mostrou que proteger o contador do emissor não substitui a persistência do histórico de recepção. Com emissor C1, o histórico volátil permitiu a aceitação dos 1.200 replays selecionados, enquanto o persistente rejeitou todos os 2.400 recebidos. Em F5, observou-se uma amostra sem evento de entrega por execução, sem duplicatas entregues, comportamento compatível com confirmação persistente anterior à falha e rejeição da reentrega. A confirmação independente do estado recuperado, prevista na metodologia, exige instrumentação adicional.
>
> Assim, os resultados sustentam a hipótese de redução do custo de persistência no emissor sem violação observada da unicidade dos nonces nas configurações protegidas. Não estabelecem um tamanho de reserva universalmente ótimo: blocos maiores reduziram as transações, mas ampliaram o descarte possível, e os instantes de falha escolhidos favoreceram alinhamentos específicos. As conclusões se limitam ao ambiente em software, às falhas de processo exercitadas e às métricas preservadas.

Somando todas as campanhas, as configurações protegidas abrangem **610 execuções e 361.810 cifragens sem reutilização registrada**. Esse total inclui C1 nos controles com receptor volátil: “emissor protegido” não equivale a “sistema protegido contra replay”.

## 11. Gráficos que melhor sustentam a análise

Os arquivos abaixo mantêm valores numéricos sem arredondamento editorial. Não é necessário executar novamente as simulações para gerar os gráficos.

| Prioridade | Gráfico | Dados e construção | Consideração que evidencia |
|---|---|---|---|
| 1 | Barras de transações por configuração, separando emissor e receptor | Filtrar `continuous`; usar `emitter_transactions` e `receiver_transactions`. Anotar reduções frente a C1. C0=0 exige cuidado se usar escala logarítmica | Economia no emissor e custo que permanece no receptor |
| 2 | Pontos individuais por repetição + mediana e intervalo para preparação | Filtrar `continuous`; painéis separados para `prep_median_us` e `prep_p95_us`, dez pontos por configuração | Magnitude do ganho e variação entre execuções |
| 3 | Reutilizações e fração de amostras entregues versus posição da falha | Filtrar `emitter_restart`; eixo x=250/500/750; curvas separadas para C0 e políticas protegidas | Violação no emissor e impacto na disponibilidade, sem confundir as duas métricas |
| 4 | Descarte em função da posição dentro da reserva | Filtrar `directed`, ponto F3; comparar primeira cifragem, fim da primeira reserva e início da segunda para cada B | Custo de abandonar a reserva e efeito de B; acrescentar F2 em painel separado com valores inferidos identificados |
| 5 | Barras de proporção de replay aceito por cenário/histórico | Usar `resumo_replay.csv`, `accepted_over_reached`; anotar numerador/denominador | Separação entre histórico volátil e persistente |
| 6 | Recuperação com observações individuais e contagem de casos fora do limite | Usar `execucoes.csv`, expandindo `recovery_s`; separar campanhas e mostrar 30 casos nulos de C0 como categoria própria | Recuperação observada sem tratar censura como tempo zero ou dez segundos exatos |
| 7 | Quadro comparativo F4/F5 de amostras com e sem evento de entrega | Filtrar `receiver_restart`; 1.000/0 versus 999/1 por execução | Segurança contra repetição não implica entrega exatamente uma vez |

Não montar boxplots de “latência de mensagens” a partir de dez medianas: esses pontos representam **resumos de execuções**. Não converter `null` de recuperação para zero, não misturar dirigidos de tamanhos diferentes com os ensaios de 1.000 mensagens e não colocar estimativas de commits em F2/F5 na mesma série de medições sem distinção visual. Para comparar B, mostrar tanto os instantes fixos da campanha F3 quanto as fronteiras dos dirigidos evita esconder o alinhamento favorável de 64 e 256.

## 12. Arquivos derivados e reprodução da análise

| Arquivo | Conteúdo |
|---|---|
| [analisar.py](analisar.py) | Auditoria e agregação, somente biblioteca padrão de Python; não inicia simulações e não altera os CSVs originais |
| [execucoes.csv](dados/execucoes.csv) | 670 linhas, coluna `campaign`, perda total derivada e ressalvas por linha em `measurement_caveats` |
| [resumo_cenarios.csv](dados/resumo_cenarios.csv) | 67 cenários; mediana, mínimo e máximo das métricas; recuperações e rejeições/perdas agregadas |
| [resumo_replay.csv](dados/resumo_replay.csv) | Seis grupos do receptor, com numerador/denominador e tempos agrupados sobre 30 execuções |
| [auditoria.json](dados/auditoria.json) | Contagens, parâmetros, hashes dos dados e do código inspecionado, confirmação dos backups preservados |

A partir da raiz do repositório:

```bash
.venv/bin/python analise/analisar.py
```

O script exige o conjunto completo de 10 repetições, 1.000 amostras nominais e 10 mensagens/s, verifica os casos dirigidos com seus tamanhos próprios e falha se encontrar identidades duplicadas, casos faltantes ou contagens inconsistentes. As colunas numéricas resumidas conservam os valores registrados; **não aplicam as correções inferidas para F2/F5**. Os hashes do código correspondem à versão inspecionada na análise, não certificam a versão usada historicamente em cada execução.

Os arquivos de origem em `results/` estão ignorados pelo Git conforme a configuração do projeto. Para arquivamento acadêmico, preservar também os quatro CSVs originais, `parameters.json`, `resume.log` e o relatório parcial junto da versão do código; apenas os arquivos derivados não substituem toda a proveniência experimental.
