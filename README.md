# check-block

Минималистичный диагностический скрипт для проверки блокировок на уровне TCP, TLS, сертификата и HTTP. Без зависимостей — только стандартная библиотека Python.

Полезен для диагностики блокировок ТСПУ, проверки REALITY-нод и маскирующих прокси.

## Что проверяет

Все четыре уровня проходят **за одно TCP-соединение**:

| Шаг  | Что происходит | Что значит результат |
|------|---------------|----------------------|
| TCP  | `socket.connect()` | дропается ли IP:port |
| TLS  | TLS handshake с передачей SNI в ClientHello | режет ли DPI по fingerprint/SNI |
| CERT | совпадение CN/SAN с SNI, срок действия | правильный ли сертификат на ноде |
| HTTP | `GET /` через тот же TLS-сокет | доходит ли реальный трафик |

## Использование

```bash
python3 check_block.py <ip> <port> [sni] [--timeout сек]
```

```bash
# Только TCP + TLS, без проверки сертификата
python3 check_block.py 213.155.12.140 443

# Полная проверка с SNI
python3 check_block.py 213.155.12.140 8443 chksum.net

# Увеличенный таймаут
python3 check_block.py 217.177.34.139 443 rijksoverheid.nl --timeout 10
```

## Пример вывода

```
Target : 123.123.123.123:2083
SNI    : mysni.net
--------------------------------------------
✓  TCP    OK        (51 ms)
✓  TLS    OK        (83 ms)
       version : TLSv1.3
       cipher  : TLS_AES_256_GCM_SHA384
✓  CERT   OK
       CN      : mysni.net
       SANs    : mysni.net, mail.mysni.net
       SNI     : ✓ mysni.net
       expires : ✓ Jun 19 07:20:17 2026 GMT  (61д)
✓  HTTP   OK        (114 ms) — HTTP/1.1 200 OK
--------------------------------------------
```

## Интерпретация результатов

| Картина | Вывод |
|---------|-------|
| `✗ TCP TIMEOUT` | IP дропается — блокировка или firewall |
| `✗ TCP REFUSED` | Порт закрыт |
| `✓ TCP` + `✗ TLS TIMEOUT` | DPI режет по fingerprint или SNI |
| `✓ TCP` + `✗ TLS RST` | Активная блокировка — мгновенный RST |
| `✓ TCP` + `✓ TLS` + `✗ CERT FAIL` | Сервер отдаёт чужой сертификат |
| `✓ TCP` + `✓ TLS` + `⚠ HTTP FAIL — 400` | Нода живая, 400 — норма для REALITY (nginx catch-all) |
| `✓ TCP` + `✗ TLS ssl error: WRONG_VERSION_NUMBER` | На порту не TLS (plain HTTP транспорт или другой протокол) |

## Требования

- Python 3.9+
- Зависимостей нет
