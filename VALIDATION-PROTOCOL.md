# Protocolo de validação dos scanners

## Objetivo e estado atual

Este pacote serve de guia para uma revisão independente. Não é um resultado de
benchmark, uma certificação nem uma prova de que um scanner deteta uma
vulnerabilidade real. Durante a preparação deste protocolo, nenhum scanner foi
executado contra uma aplicação externa.

Na versão `0.3.0`, o repositório regista 60 scanners:

- 13 estão na lista permitida como passivos em
  `ScanManager.PASSIVE_SCANNER_NAMES`.
- Os outros 47 só são incluídos quando o modo completo/ativo está ativado.
  Esta é a classificação de execução do projeto, não uma afirmação de que cada
  scanner usa uma técnica específica.
- Cinco têm casos de teste sintéticos locais. Os outros 55 não têm esses casos
  na matriz de validação atual. Testes sintéticos são testes de regressão, não
  evidência independente obtida em aplicações vulneráveis e limpas.

`tests/data/scanner-validation-template.csv` é o modelo para registar os casos.
Começa com uma linha por scanner, ainda não testada. Duplique uma linha para
cada caso de aplicação com resultado esperado definido independentemente; não
substitua as linhas de referência.

## Independência e referência esperada

1. Selecione aplicações de treino ou benchmark alojadas localmente, com estados
   vulneráveis e limpos documentados e reproduzíveis. Registe a versão exata,
   o digest da imagem (se aplicável), a configuração e o procedimento de
   reposição.
2. Antes de executar o WebsiteAttack, um revisor que não tenha implementado o
   scanner regista o resultado esperado e uma justificação concisa para cada
   caso. Mantenha estes rótulos separados da pessoa que opera a ferramenta.
3. Peça a um segundo revisor para decidir casos em disputa e analisar uma
   amostra dos resultados positivos e negativos. Registe as funções dos
   revisores; uma autoavaliação não deve ser descrita como independente.
4. Mantenha os alvos numa rede local isolada, bloqueie o tráfego de saída, use
   contas e dados sintéticos e crie uma cópia instantânea do estado para repor
   entre casos. Mantenha uma lista permitida dos anfitriões e portas do
   laboratório. Não aponte a bateria para sites públicos, produção, serviços
   de terceiros, metadados cloud ou dados reais de utilizadores.
5. Comece apenas com verificações passivas. Qualquer caso que exija pedidos
   ativos precisa da aprovação documentada do responsável pelo laboratório,
   de uma revisão explícita de segurança e das ações, de um estado descartável
   para reposição e da presença de um operador humano. Não execute casos que
   alterem dados, carreguem ficheiros, bloqueiem contas ou sejam destrutivos,
   salvo se o responsável pelo laboratório os tiver concebido especificamente
   para poderem ser repostos em segurança.
6. Fixe o commit/versão do WebsiteAttack, a versão do Python, as versões ou o
   estado das dependências, a versão/imagem da aplicação, as definições da
   análise e os rótulos dos casos. Preserve relatórios sanitizados e o
   mapeamento exato entre casos e resultados.
7. Congele os rótulos e o plano de análise antes de consultar os resultados.
   Não ajuste um scanner com os mesmos casos usados para calcular os
   resultados finais. Depois de qualquer alteração às regras, use um conjunto
   de casos separado e reservado para validação.

## Definição dos casos e cálculo dos resultados

Cada linha representa um scanner aplicado a um estado de uma aplicação e a um
conjunto de endpoints/rotas. O caso tem de ser aplicável ao scanner. Registe
`not_applicable`, `error` ou `skipped` separadamente; nenhum destes estados
conta como verdadeiro ou falso positivo. Conte, no máximo, uma deteção por
scanner e por caso, mesmo que sejam gerados vários resultados duplicados.
Guarde os identificadores dos resultados à parte.

| Resultado esperado | Resultado observado | Classificação |
|---|---|---|
| `positive` | `finding` | VP / TP (verdadeiro positivo) |
| `positive` | `no_finding` | FN (falso negativo) |
| `negative` | `finding` | FP (falso positivo) |
| `negative` | `no_finding` | VN / TN (verdadeiro negativo) |

Para cada scanner, publique as quatro contagens brutas e a lista de casos. Nas
fórmulas abaixo, `TP` corresponde a VP e `TN` corresponde a VN. Calcule:

- Precisão: `TP / (TP + FP)`
- Sensibilidade/recall: `TP / (TP + FN)`
- Especificidade: `TN / (TN + FP)`
- Taxa de falsos positivos: `FP / (FP + TN)`

Se um denominador for zero, registe a métrica como `N/A`; não substitua o
resultado por zero. Inclua intervalos de confiança e o tamanho da amostra junto
de cada taxa. Não agregue scanners, famílias de aplicações ou modos passivo e
ativo diferentes numa única pontuação geral. Apresente separadamente os erros,
os casos ignorados/não aplicáveis e a cobertura. Um resultado limpo numa amostra
pequena não demonstra fiabilidade.

Defina os limiares de utilização pretendida, os tamanhos mínimos das amostras,
as regras de inclusão/exclusão e o tratamento de resultados duplicados antes
de iniciar o benchmark. Um scanner que falhe um caso ou produza um falso
positivo precisa de análise caso a caso e de testes de regressão; não deve ser
removido silenciosamente do relatório.

## Entregáveis exigidos ao revisor

O revisor independente deve entregar:

1. Um CSV preenchido com os casos e um resumo assinado e datado do ambiente e
   da metodologia do benchmark.
2. VP/FP/VN/FN por scanner, precisão, sensibilidade/recall, especificidade,
   taxa de falsos positivos, intervalos de confiança e contagens de casos
   aplicáveis/com erro/ignorados.
3. Relatórios exportados e sanitizados, mais os identificadores dos casos para
   cada divergência.
4. Uma lista das alterações às regras feitas após a execução inicial e os
   resultados obtidos num conjunto de casos separado e reservado.
5. Uma declaração escrita das limitações e uma decisão para cada scanner:
   `reviewed_for_limited_use`, `needs_changes` ou `not_evaluated`.

O revisor não deve declarar o produto ou todos os scanners «certificados» com
base apenas neste exercício. Alegações de certificação exigem um esquema de
garantia definido, evidência representativa e uma organização responsável. Este
CSV, por si só, não oferece certificação.

## Inventário e estado dos testes locais atuais

O CSV associado contém os nomes e as famílias dos scanners, o modo de execução
e o rótulo inicial de validação. `synthetic_only` significa apenas que existem
testes de regressão sintéticos locais; `not_independently_validated` significa
que o repositório não contém atualmente evidência de benchmark independente
em aplicações para esse scanner. Estes rótulos não são resultados de testes.
