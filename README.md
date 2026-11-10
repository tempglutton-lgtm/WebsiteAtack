# WebsiteAttack

Ferramenta local para rastrear um site e executar verificações automatizadas de segurança. Este guia mostra como iniciar a aplicação no Windows 11 e experimentar o fluxo com o site de demonstração incluído no repositório.

> **Use somente em sistemas seus ou para os quais você tenha autorização explícita.** As verificações enviam requisições ao alvo e podem afetá-lo. O exemplo deste guia usa apenas um site local de teste; não use dados ou credenciais reais.

## Requisitos

- Windows 11
- Python 3.10 ou superior, disponível pelo comando `py` (testado em Python 3.15.2)
- PowerShell

Para verificar se o Python está instalado, abra o PowerShell e execute:

```powershell
py --version
```

Para selecionar explicitamente o Python 3.15 instalado, verifique-o com `py -3.15 --version`.

Se o comando não for reconhecido, instale o Python pelo [python.org](https://www.python.org/downloads/) e habilite a opção para adicioná-lo ao `PATH` durante a instalação. Depois, abra uma nova janela do PowerShell.

## 1. Instalar as dependências

Abra o PowerShell na pasta do projeto. Por exemplo:

```powershell
cd "$HOME\Documents\WebsiteAtack"
```

Crie um ambiente virtual e instale as dependências:

```powershell
py -3.15 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

O comando acima cria o ambiente com Python 3.15. Se preferir outra versão suportada (3.10 ou superior), substitua `py -3.15` por `py`. Usar o executável do ambiente virtual diretamente evita precisar alterar a política de execução de scripts do PowerShell.

## 2. Iniciar a aplicação

Na mesma janela do PowerShell, execute:

```powershell
.\.venv\Scripts\python.exe main.py
```

O servidor fica disponível somente neste computador, em `http://127.0.0.1:8000`. A interface e a API rejeitam ligações remotas. Mantenha essa janela aberta e acesse o endereço no navegador.

## 3. Iniciar o site de demonstração

Para testar sem acessar um site externo, abra uma **segunda** janela do PowerShell, vá até a pasta do projeto e inicie o servidor local do site de demonstração:

```powershell
cd "$HOME\Documents\WebsiteAtack"
py -m http.server 8080 --bind 127.0.0.1 --directory testsite
```

O site de demonstração ficará disponível em `http://127.0.0.1:8080`. Mantenha também essa janela aberta enquanto a varredura estiver em andamento.

## 4. Fazer uma varredura local

1. No navegador, abra `http://127.0.0.1:8000`.
2. No campo **URL do alvo**, informe `http://127.0.0.1:8080/`.
3. Marque **Confirmo que tenho autorização explícita para avaliar este alvo**.
4. Selecione **INICIAR ANÁLISE**.
5. Acompanhe o progresso e, ao concluir, consulte os resultados exibidos.

A interface mostra o progresso, o endereço atual, o número de requisições e os endpoints descobertos. O site de demonstração contém páginas HTML simples; portanto, os resultados servem para experimentar a ferramenta, não como avaliação de um site real.

O formulário tem apenas o URL e a confirmação de autorização. A ferramenta usa configuração predefinida, executa verificações passivas, não autentica e não executa testes ativos. Uma varredura por vez é permitida. O limite de requisições aplica-se ao rastreador, às verificações e a cada redirecionamento seguido; há limites máximos de páginas, profundidade, concorrência e ritmo. O escopo é a mesma origem da URL informada (esquema, host e porta); pedidos ou redirecionamentos fora desse escopo são bloqueados. Corpos de resposta acima de 2 MiB são rejeitados para limitar o consumo de memória. A API rejeita opções adicionais de varredura. Falhas e avisos são mostrados no resultado: se houver algum, considere a varredura incompleta e investigue antes de interpretar os achados.

O cancelamento interrompe a execução, mas não desfaz eventuais efeitos indiretos de pedidos ao alvo. Mesmo verificações passivas podem gerar tráfego ou registos no serviço.

Cada relatório inclui um identificador, horários, versão da ferramenta e dependências, configuração, mapa de scanners selecionados/excluídos, contagens, avisos e estado da execução. `execution_complete` significa apenas que o fluxo terminou sem as condições conhecidas de execução parcial; **não significa que o alvo foi coberto por completo ou que está seguro**. Os formatos JSON, CSV e PDF incluem as limitações e orientações para repetir e verificar manualmente os indicadores. O inventário exportado não contém corpos de resposta e os valores das query strings são ocultados; padrões comuns de credenciais em texto também são ocultados. Ainda assim, trate relatórios como dados sensíveis e guarde-os em local controlado.

O PDF começa com um resumo preliminar para partilha: apresenta o número de indicadores, o estado da execução e a triagem registada, mas esclarece que nenhum destes elementos prova por si só que o site é seguro ou inseguro. Também regista que a autorização foi declarada pelo utilizador, não verificada pela ferramenta. Valide os resultados com o proprietário antes de os comunicar. O scanner não avalia design, acessibilidade ou usabilidade; qualquer proposta de webdesign deve basear-se numa avaliação separada e transparente.

A aplicação grava eventos operacionais sem credenciais em `%USERPROFILE%\.websiteattack\audit.jsonl` (ou no caminho definido por `WEBSITEATTACK_AUDIT_PATH`) e remove entradas com mais de 90 dias quando grava novos eventos. O registo inclui início/fim, escopo sanitizado, configuração e decisões de triagem, mas **não é assinado nem inviolável**. Restrinja as permissões da pasta e aplique a política de retenção da organização. Relatórios e notas de revisão ficam na memória até serem exportados; exporte-os para armazenamento aprovado antes de fechar ou reiniciar a aplicação.

Os resultados são indicadores heurísticos, não vulnerabilidades confirmadas; a pontuação do scanner não é uma probabilidade calibrada. Não é possível garantir que uma ocorrência seja uma vulnerabilidade real sem reproduzir e validar o comportamento. A ferramenta também pode não detetar vulnerabilidades existentes. A ausência de ocorrências não prova que o site é seguro.

Confirme manualmente cada indicador e combine a ferramenta com uma revisão profissional antes de tomar decisões de segurança ou entregar conclusões a um cliente. Uma execução com mais páginas não torna automaticamente os achados mais certos.

## 5. Consultar e exportar resultados

- Use a pesquisa e o filtro de severidade para limitar as ocorrências exibidas.
- Expanda **Como verificar e confirmar** num indicador para ver o roteiro de triagem específico.
- Selecione **JSON**, **CSV** ou **PDF** para baixar o relatório, incluindo metadados para auditoria.
- O JSON é exportado com indentação e secções de nível superior (`report`, `summary`, `endpoints`, `findings` e `errors`) para facilitar a leitura; os dados e nomes dos campos mantêm-se.
- Use **PARAR ANÁLISE** para interromper uma execução em andamento.
- Em cada ocorrência, registe o resultado da triagem, o revisor e uma nota com evidência/limitações. Esse registo é uma declaração do revisor, não uma confirmação automática nem uma identidade autenticada; faça a exportação depois de rever.

## Confirmar um indicador

Cada indicador inclui o scanner que o originou, evidência observada e uma orientação de triagem por família. Essa orientação é genérica: não é um teste específico garantido para a regra, nem uma receita de exploração. Leia a evidência e o nome do scanner; se os passos não se aplicarem ao caso concreto, não os improvise — peça validação ao responsável técnico. Compare com um comportamento de referência e exija evidência reproduzível de impacto. Reflexão de texto, um cabeçalho ausente ou uma pontuação elevada, isoladamente, não provam uma vulnerabilidade.

As ferramentas abaixo ajudam a inspecionar evidência; nenhuma confirma automaticamente uma vulnerabilidade:

- [**OWASP ZAP Passive Scan**](https://www.zaproxy.org/docs/desktop/start/features/pscan/) analisa mensagens que passam pelo ZAP; não é prova de explorabilidade. Não confunda com o Active Scan, que envia ataques de teste.
- [**Burp Suite Community Repeater**](https://portswigger.net/burp/documentation/desktop/tools/repeater) permite editar e reenviar pedidos. Um pedido GET também pode ter efeitos num site mal implementado; use staging e contas/dados descartáveis, exceto quando o responsável autorizar expressamente uma verificação de leitura em produção.
- [**Chrome DevTools Network**](https://developer.chrome.com/docs/devtools/network/) ou [**Microsoft Edge DevTools Network**](https://learn.microsoft.com/microsoft-edge/devtools/network/) ajudam a inspecionar pedidos, respostas e cabeçalhos. Não comprovam, por si sós, regras de autorização ou comportamento interno do servidor.
- **Logs e revisão de código com o responsável pelo serviço** são importantes para corroborar causas e decisões server-side.

O perfil exposto pela aplicação seleciona uma lista limitada de scanners passivos; os scanners ativos aparecem no mapa de cobertura como excluídos. Não ative testes ativos nesta ferramenta sem uma alteração explícita de escopo, autorização e validação de segurança.

O relatório escolhe uma orientação pelo tipo do scanner. Em termos gerais:

- **Reconhecimento:** confirme que a rota/tecnologia existe e está no âmbito. Uma rota descoberta é uma observação, não uma vulnerabilidade por si só.
- **Injeção:** compare com uma resposta de referência em staging usando apenas entradas benignas aprovadas; procure efeito causal repetível e confirme nos logs/código. Não use ferramentas de exploração automática nem tente aceder, alterar ou apagar dados.
- **Browser (XSS, HTML, redirecionamento, framing):** inspecione o contexto no DevTools e use marcadores inertes. Um marcador refletido não confirma XSS; uma confirmação de execução só deve ser feita por pessoa qualificada em staging isolado, com autorização explícita. Para redirecionamento, compare a resposta e o cabeçalho `Location` sem seguir o destino; nunca use um domínio de terceiros como destino de teste.
- **Controlo de acesso:** use duas contas de teste com permissões distintas e apenas pedidos de leitura; confirme uma violação face à matriz de acesso aprovada. Nunca use dados de outros utilizadores.
- **Autenticação e sessão:** use contas descartáveis em staging; compare cookies, login e logout com a política definida. Não enumere contas nem provoque bloqueios/redefinições de utilizadores reais.
- **API/configuração:** compare respostas e cabeçalhos com a especificação e política do serviço; não envie operações de escrita nem mutações.
- **SSRF, ficheiros e comportamento server-side:** use apenas staging, logs e um endpoint de teste controlado pelo responsável. Não teste endereços internos, metadados cloud, ficheiros locais ou serviços de terceiros.

Se não conseguir reproduzir o efeito de forma segura, classifique o item como **não confirmado**, registe a razão e peça validação ao responsável técnico. Não remova essa ressalva do relatório.

## Limitações de autenticação e testes ativos

A interface não tem configuração de autenticação nem opção de testes ativos. A análise é não autenticada e passiva; a API também rejeita esses parâmetros. Aplicações que exijam login e validações que dependam de testes ativos ficam fora da cobertura desta ferramenta.

## Processo recomendado para trabalho

1. Obtenha autorização escrita do proprietário/responsável que identifique o URL/origem, período, métodos passivos permitidos e contacto para incidentes. A caixa da aplicação regista a sua declaração, mas não verifica a autorização.
2. Comece em staging isolado, com dados descartáveis, cópias de segurança e uma janela de teste aprovada. Não comece em produção.
3. Use o escopo mais restrito possível e combine a varredura passiva com a equipa responsável pelo serviço. Esta interface não oferece testes ativos.
4. Pare se aparecerem erros, comportamento inesperado, lentidão ou efeitos no estado. Investigue os avisos antes de interpretar resultados.
5. Para cada indicador, registe o pedido observado, evidência sanitizada, versão/configuração da ferramenta, passos de reprodução manual, impacto confirmado e resultado da validação. Não reporte um indicador como vulnerabilidade confirmada sem essa validação.
6. Proteja os relatórios como dados sensíveis; partilhe-os apenas com destinatários autorizados e elimine-os segundo a política acordada.
7. Faça uma revisão manual independente e, quando apropriado, confirme a correção com uma nova execução em staging.
8. Antes de entregar um relatório, obtenha aprovação de um segundo revisor e registe a aceitação ou rejeição de cada indicador.
9. Não apresente indicadores automáticos como prova de que um restaurante ou outro site é inseguro. Se oferecer webdesign, faça uma avaliação separada de design, acessibilidade e usabilidade; este scanner não avalia essas áreas e os indicadores de segurança não justificam, por si só, a venda de um redesign.

### Estado atual da validação

A suíte automatizada inclui 38 casos de fixtures sintéticas locais em cinco scanners (cabeçalhos, CSP, cookies, cache-control e clickjacking). As regras produziram **17 resultados positivos esperados e 21 resultados negativos esperados, sem divergências** neste conjunto. Isto testa apenas regras com entradas artificiais: não são resultados de aplicações vulneráveis/limpas independentes, não medem vulnerabilidades reais e não estimam precisão. Os outros 55 dos 60 scanners não têm fixtures nesta matriz. **A bateria independente pedida ainda não foi executada; a precisão geral continua não certificada.** Não interprete os valores das fixtures como desempenho em sites reais.

Para transferir a validação para um revisor independente, consulte o [protocolo e critérios de benchmark](./VALIDATION-PROTOCOL.md) e a [matriz CSV dos 60 scanners](./tests/data/scanner-validation-template.csv). São documentos de preparação; não contêm resultados de validação independente.

O mapa do relatório mostra, para cada scanner, se foi selecionado, o modo, quantos endpoints foram considerados/aplicáveis, a família de alinhamento OWASP WSTG e limitações conhecidas. Os scanners não selecionados são explicitamente indicados. A contagem de aplicabilidade é telemetria da execução, não uma medida de cobertura completa. WSTG é uma referência de organização por família; não se afirma que os casos de teste específicos do guia tenham sido implementados ou validados.

O fluxo autenticado não faz parte da interface nem da API de varredura. Testes internos de componentes antigos não significam que a ferramenta ofereça cobertura autenticada.

### Portões ainda obrigatórios antes do uso profissional

1. **Benchmark independente:** executar cada scanner em versões fixas de aplicações laboratoriais vulneráveis e limpas, com resultados esperados definidos previamente. Registar TP/FP/TN/FN por scanner, ambiente, versão da ferramenta, endpoint, evidência sanitizada e revisor. Não publicar métricas até um segundo analista rever o conjunto.
2. **Cobertura fora do modo básico:** a ferramenta não suporta autenticação nem testes ativos. Avaliações que dependam de páginas autenticadas ou validações ativas exigem outro processo e ferramentas próprias, aprovados separadamente pelo responsável pelo sistema.
3. **Revisão humana:** um pentester independente deve rever amostras positivas e negativas, regras, relatórios, limites e procedimentos de operação. Esta aprovação não ocorreu nesta alteração.
4. **Operação e dados:** aprovar escopo e janela por avaliação, proteger a pasta de auditoria e os relatórios, confirmar retenção/eliminação e exportar o relatório após a triagem.

Até estes portões serem concluídos, use o WebsiteAttack apenas como ferramenta auxiliar em staging/laboratório autorizado, com validação manual de todos os resultados. Mesmo uma execução sem erros não demonstra que o escopo inteiro foi coberto nem que o alvo está seguro.

## Encerrar

Quando terminar, pressione `Ctrl+C` em cada janela do PowerShell para parar os servidores. A aplicação não precisa ficar aberta depois do teste.

## Solução de problemas

- **`py` não é reconhecido:** instale o Python, habilite a opção para adicioná-lo ao `PATH` e abra um novo PowerShell.
- **Falha ao instalar dependências:** confirme que está na pasta do projeto e repita o comando de instalação do passo 1.
- **A porta já está em uso:** encerre o processo que está usando a porta ou reinicie o computador; a interface usa a porta `8000` e o site de demonstração usa a `8080`.
- **O site de demonstração não abre:** confirme que a janela do servidor iniciado no passo 3 continua aberta e tente `http://127.0.0.1:8080/`.
- **A varredura não inicia:** confira a URL e marque a confirmação de autorização.

## Executar os testes automatizados

Na pasta do projeto, execute:

```powershell
.\.venv\Scripts\python.exe -B -m unittest discover -s tests -v
```