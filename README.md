# claude-celular

Página estática do **Claudinho Mobile**, o mod do Claude Code que conversa com as sessões pelo celular via [ntfy](https://ntfy.sh). Cada sessão vira um chat: perguntas, atualizações e as suas mensagens em ordem, com uma caixa de mensagem só.

- Não guarda nem contém segredos: a chave nasce de um código de pareamento digitado no celular e fica só no navegador (localStorage).
- Perguntas, respostas e mensagens viajam cifradas e assinadas (`cifra.js`: SHA-256 em modo contador + HMAC-SHA256, chave derivada com PBKDF2).
- Sem scripts externos, sem analytics, sem referrer.
