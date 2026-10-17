package publish

// Languages are the locales the site is published in.
//
// Both are rendered into the same document rather than into two, so the language control
// swaps a single attribute instead of navigating. The default is baked into the markup at
// render time, so the first paint never waits on script.
var Languages = []string{"ru", "en"}

// SourcesURL is the one link on the page that leaves this origin.
//
// A constant rather than a row in the table below, because it is not a translation, and
// because a URL that appears twice is a URL that gets updated once.
const SourcesURL = "https://github.com/TuftyTech/ShellShift"

// translations is the whole string table.
//
// It is a table rather than literals in the template because the predecessor hardcoded
// Russian throughout and left dead scaffolding for a theme it never implemented; a switcher
// bolted on afterwards is how a page ends up half-translated.
var translations = map[string]map[string]string{
	"ru": {
		"title":   "ShellShift — проверенные прокси-конфигурации",
		"tagline": "Собрано из открытых источников. Опубликовано только то, что доказало работоспособность.",
		"h1":      "Прокси-конфигурации, проверенные прогоном",
		"hero_lede": "Собрано из открытых источников, поднято по одному аутбаунду в нашем процессе и " +
			"проверено HTTPS-запросом с проверкой цепочки сертификатов. Публикуется только то, что прошло.",
		"wordmark_tagline": "доказано прогоном",
		"skip":             "К содержимому",
		"nav_sources":      "Исходники",
		"cta_subs":         "Смотреть подписки",
		"cta_how":          "Как подключить",

		"not_a_vpn":      "Это не VPN-сервис",
		"not_a_vpn_body": "Проект не поднимает и не эксплуатирует ни одного сервера. Трафик идёт напрямую от вашего клиента к чужому узлу. Операторы этих узлов нам неизвестны и могут видеть то, что через них проходит.",

		"what_we_check":     "Что именно проверено",
		"funnel_collected":  "собрано",
		"funnel_decoded":    "разобрано",
		"funnel_candidates": "уникальных",
		"funnel_policy":     "прошло политику",
		"funnel_reached":    "достижимо",
		"funnel_proven":     "доказано",
		"funnel_note":       "Каждый узел поднимался как отдельный аутбаунд в нашем процессе и должен был выполнить HTTPS-запрос с проверкой цепочки сертификатов. Узел, который вмешивается в соединение, эту проверку не проходит.",

		"subscriptions": "Подписки",
		"nodes_one":     "узел",
		"nodes_few":     "узла",
		"nodes_many":    "узлов",
		"copy":          "Копировать",
		"copied":        "Скопировано",

		"bundle_note_all": "Все проверенные узлы, отсортированные по задержке.",
		"bundle_note_wl": "Только Reality-узлы, чей SNI есть в белом списке цензора и чья " +
			"маскировка подтверждена: сайт из SNI действительно существует и отдаёт валидный " +
			"сертификат на своё имя. Проверяется напрямую, а не через узел.",

		"bundle_note_vless": "VLESS с Reality или TLS — самый распространённый протокол в этой " +
			"выборке и обычно самый живучий против DPI. Берите этот файл, если клиент не " +
			"понимает остальные или нужен один протокол вместо смеси.",
		"bundle_note_vmess": "VMess — предшественник VLESS: собственное шифрование поверх TCP и " +
			"более заметное рукопожатие. Держится хуже, но некоторые старые клиенты умеют " +
			"только его.",
		"bundle_note_trojan": "Trojan прикидывается обычным HTTPS-сервером: тот же 443 и " +
			"настоящий TLS, без своего рукопожатия. Разумный второй вариант, когда " +
			"VLESS-узлы в вашей сети не идут.",
		"bundle_note_ss": "Shadowsocks — простой шифрованный туннель без TLS-маскировки. " +
			"Быстрый и неприхотливый, но узнаваемый для DPI, поэтому годится там, где " +
			"блокировка мягче.",
		"bundle_note_hy2": "Hysteria2 работает по QUIC, то есть по UDP, и выигрывает на потерях. " +
			"Обычно этот файл пуст: UDP режут целиком, и до доказательства не доходит ни один " +
			"такой узел.",

		"class_note_unavailable": "Белый список не загрузился в этом прогоне, поэтому проверка " +
			"не выполнялась. Это пусто из-за сбоя загрузки, а не потому что ни один узел не подошёл.",
		"class_note_unconfigured": "Классификатор не был настроен в этом прогоне: проверка " +
			"маскировки не выполнялась ни для одного узла.",
		"class_note_not_reality": "Ни один из проверенных узлов не использует Reality, а " +
			"маскировка есть только у него.",
		"class_note_not_listed": "Reality-узлы есть, но их SNI не встречается в белом списке " +
			"цензора — маскировка под сайт, который и так блокируется, ничего не даёт.",
		"class_note_unproven": "SNI нашлись в белом списке, но маскировку подтвердить не " +
			"удалось: сайт не отвечает или отдаёт сертификат не на своё имя.",

		"howto":         "Как подключить",
		"howto_1":       "Скопируйте ссылку любой подписки выше.",
		"howto_2":       "Вставьте её в клиент как подписку, а не как отдельный сервер.",
		"howto_3":       "Обновите подписку в клиенте. Список пересобирается каждые четыре часа.",
		"howto_4":       "Если узел перестал отвечать — обновите подписку ещё раз, а не ищите причину: узлы чужие и исчезают без предупреждения.",
		"howto_clients": "Подойдёт любой клиент, который понимает подписки",
		"howto_note":    "Проект не связан с этими клиентами и не поддерживает их.",

		"mix":          "Состав каталога",
		"protocols":    "Протоколы",
		"inventory":    "Проверенные узлы",
		"filter":       "Фильтр по протоколу",
		"filter_all":   "Все",
		"search":       "Поиск по узлам",
		"shown":        "Показано",
		"no_match":     "Под фильтр не попал ни один узел.",
		"col_protocol": "Протокол",
		"col_country":  "Страна",
		"col_trans":    "Транспорт",
		"col_id":       "ID",
		"col_latency":  "Задержка, мс",
		"col_streak":   "Серия",
		"col_verified": "Проверено",
		"masked":       "маскировка проверена",
		"mbps_note":    "Вторая строка в колонке задержки — Мбит/с, если пропускная способность измерялась.",

		"countries":         "Страны",
		"ago_hours":         "ч назад",
		"freshness_live":    "свежие данные",
		"freshness_aging":   "данные стареют",
		"freshness_stale":   "данные устарели — конвейер мог остановиться",
		"freshness_unknown": "время обновления неизвестно",
		"engine":            "Движок",
		"run_took":          "Прогон занял",
		"seconds":           "с",
		"budget_warning":    "Прогон не успел проверить всех кандидатов: доходность ниже — нижняя граница, а не измерение.",
		"empty":             "Пока нечего показать: ни один прогон не завершился.",
		"language":          "Язык",
		"theme":             "Тема",

		// --- the node card -------------------------------------------------------------
		"detail_open":   "Подробнее",
		"detail_title":  "Узел",
		"detail_close":  "Закрыть",
		"detail_copy":   "Копировать ссылку",
		"detail_reveal": "Показать",
		"detail_hide":   "Скрыть",
		"detail_secret_note": "Ключ доступа и адрес сервера скрыты. Они есть в подписке, " +
			"которую и так может открыть любой, — здесь они спрятаны, чтобы не уехать в чужой " +
			"скриншот вместе с окном.",
		"detail_absent": "Нет данных",

		"detail_sec_conn":  "Подключение",
		"detail_sec_net":   "Сеть и расположение",
		"detail_sec_proof": "Что проверено",
		"detail_sec_class": "Класс и маскировка",

		"detail_uri":             "Ссылка",
		"detail_server":          "Сервер",
		"detail_port":            "Порт",
		"detail_port_range":      "Диапазон портов",
		"detail_security":        "Шифрование",
		"detail_sni":             "SNI",
		"detail_host":            "Host-заголовок",
		"detail_path":            "Путь",
		"detail_pbk":             "Публичный ключ Reality",
		"detail_sid":             "Short ID",
		"detail_fp":              "Отпечаток TLS",
		"detail_alpn":            "ALPN",
		"detail_flow":            "Flow",
		"detail_packet_encoding": "Кодирование UDP-пакетов",
		"detail_aid":             "AlterID",
		"detail_obfs":            "Обфускация",
		"detail_method":          "Шифр",
		"detail_plugin":          "Плагин",
		"detail_credential":      "Ключ доступа",

		"detail_addr":   "IP-адрес",
		"detail_ptr":    "Обратная запись DNS",
		"detail_asn":    "Автономная система",
		"detail_asname": "Имя AS",
		"detail_isp":    "Провайдер",
		"detail_org":    "Владелец сети",
		"detail_place":  "Расположение",
		"detail_tz":     "Часовой пояс",

		"detail_latency":    "Задержка",
		"detail_mbps":       "Скорость",
		"detail_bytes":      "Передано",
		"detail_streak":     "Серия прогонов подряд",
		"detail_proofs":     "Проверок пройдено",
		"detail_failures":   "Отказов",
		"detail_first_seen": "Впервые замечен",
		"detail_stages":     "Этапы проверки",

		"detail_class":         "Класс",
		"detail_class_reason":  "Почему этот класс",
		"detail_cover_subject": "Сертификат выдан на",
		"detail_cover_issuer":  "Кем выдан",
		"detail_cover_valid":   "Срок действия",
		"detail_cover_tls":     "Версия TLS",
		"detail_source":        "Источник",

		"legal": "Правовая информация",
		"legal_lede": "Прочитайте это перед использованием. Ниже — что этот проект делает, " +
			"чего он не делает и что остаётся на вашей стороне.",
		"legal_role": "Не сервис, не оператор связи, не VPN",
		"legal_role_body": "Проект не эксплуатирует серверов, не маршрутизирует и не " +
			"проксирует трафик, не предоставляет услуг связи и не берёт денег. Это статическая " +
			"страница и текстовые файлы со ссылками. Соединение устанавливает ваш клиент " +
			"напрямую с чужим узлом; проект в этом соединении не участвует.",
		"legal_source": "Данные собраны из открытых источников",
		"legal_source_body": "Все конфигурации уже были опубликованы третьими лицами в " +
			"общедоступных источниках. Проект их не создаёт, не покупает, не продаёт и не " +
			"заказывает. Он проверяет работоспособность уже опубликованного и показывает " +
			"результат проверки.",
		"legal_relation": "Никакой связи с операторами узлов",
		"legal_relation_body": "Владельцы и операторы узлов проекту неизвестны, с ним не " +
			"связаны и о нём не осведомлены. Проект не контролирует их узлы, не отвечает за " +
			"их действия и не может ничего от них потребовать.",
		"legal_no_data": "Ни аккаунтов, ни платежей, ни персональных данных",
		"legal_no_data_body": "Регистрации нет, оплаты нет, cookie нет, аналитики нет, " +
			"счётчиков нет. Сайт не собирает и не хранит персональных данных, не ведёт " +
			"журналов посещений и не имеет журналов трафика — трафик через него не идёт.",
		"legal_no_warranty": "Без гарантий",
		"legal_no_warranty_body": "Всё предоставляется «как есть», без каких-либо гарантий: " +
			"работоспособности, доступности, безопасности, конфиденциальности или пригодности " +
			"для любой цели. Проверка означает, что узел провёз один HTTPS-запрос в момент " +
			"измерения, и больше ничего. Риск использования — на пользователе.",
		"legal_user": "Ответственность пользователя",
		"legal_user_body": "Соблюдение законов вашей юрисдикции — ваша ответственность. " +
			"Проект не побуждает нарушать закон, не предназначен для противоправных действий " +
			"и не предоставляется для них. Если использование таких конфигураций у вас " +
			"запрещено — не используйте их.",
		"legal_operator": "Оператор узла видит ваш трафик",
		"legal_operator_body": "Промежуточный узел — это чужой сервер. Он видит адреса, к " +
			"которым вы обращаетесь, и может видеть содержимое всего, что не защищено " +
			"сквозным шифрованием. Не передавайте через такие узлы пароли, платёжные и другие " +
			"чувствительные данные и не считайте это анонимностью.",
		"legal_takedown": "Запросы на удаление и жалобы",
		"legal_takedown_body": "Если вы правообладатель или оператор узла и хотите, чтобы " +
			"ссылка была убрана — напишите в issues репозитория. Обоснованные обращения " +
			"выполняются: запись удаляется из публикуемых списков при следующем прогоне.",
		"legal_marks": "Товарные знаки и имена",
		"legal_marks_body": "Названия протоколов, клиентов, сайтов и компаний принадлежат их " +
			"владельцам и используются только для указания на предмет. Проект с ними не " +
			"связан, ими не одобрен и их не представляет.",
		"legal_not_advice": "Этот текст — не юридическая консультация и не может ей быть. Он " +
			"описывает устройство проекта, а не ваши права и обязанности в вашей стране. " +
			"Полностью снять правовые риски он не может: за оценкой своей ситуации обращайтесь " +
			"к юристу своей юрисдикции.",
	},
	"en": {
		"title":   "ShellShift — verified proxy configurations",
		"tagline": "Collected from public sources. Only what proved it works is published.",
		"h1":      "Proxy configurations proven by a run",
		"hero_lede": "Collected from public sources, raised one outbound at a time inside our " +
			"process and made to complete an HTTPS request with a verified certificate chain. " +
			"Only what passed is published.",
		"wordmark_tagline": "proven by a run",
		"skip":             "Skip to content",
		"nav_sources":      "Sources",
		"cta_subs":         "Browse subscriptions",
		"cta_how":          "How to connect",

		"not_a_vpn":      "This is not a VPN service",
		"not_a_vpn_body": "The project runs no servers of its own. Traffic goes straight from your client to a node somebody else operates. Those operators are unknown to us and can see what passes through them.",

		"what_we_check":     "What was actually checked",
		"funnel_collected":  "collected",
		"funnel_decoded":    "decoded",
		"funnel_candidates": "distinct",
		"funnel_policy":     "passed policy",
		"funnel_reached":    "reachable",
		"funnel_proven":     "proven",
		"funnel_note":       "Every node was raised as its own outbound inside our process and made to complete an HTTPS request with a verified certificate chain. A node that interferes with the connection fails that check.",

		"subscriptions": "Subscriptions",
		"nodes_one":     "node",
		"nodes_few":     "nodes",
		"nodes_many":    "nodes",
		"copy":          "Copy",
		"copied":        "Copied",

		"bundle_note_all": "Every proven node, ordered by latency.",
		"bundle_note_wl": "Only Reality nodes whose SNI is on the censor's whitelist and whose " +
			"disguise checked out: the site the SNI names really is there and really serves a " +
			"valid certificate for that name. Checked directly, not through the node.",

		"bundle_note_vless": "VLESS over Reality or TLS — the most common protocol in this " +
			"corpus and usually the most durable against DPI. Take this file if your client " +
			"understands nothing else, or you want one protocol rather than a mixture.",
		"bundle_note_vmess": "VMess is VLESS's predecessor: its own encryption over TCP and a " +
			"more conspicuous handshake. It survives less well, but some older clients speak " +
			"only this.",
		"bundle_note_trojan": "Trojan pretends to be an ordinary HTTPS server: the same port 443 " +
			"and real TLS, with no handshake of its own. A sensible second choice when the " +
			"VLESS nodes will not carry traffic on your network.",
		"bundle_note_ss": "Shadowsocks is a plain encrypted tunnel with no TLS disguise. Fast " +
			"and undemanding, but recognisable to DPI, so it is for places where the filtering " +
			"is softer.",
		"bundle_note_hy2": "Hysteria2 runs over QUIC, which is UDP, and wins where there is " +
			"packet loss. This file is usually empty: UDP is blocked wholesale, and no such " +
			"node reaches the proof.",

		"class_note_unavailable": "The whitelist did not load in this run, so the check never " +
			"ran. This is empty because a feed failed, not because no node qualified.",
		"class_note_unconfigured": "No classifier was configured for this run: masking was not " +
			"checked for any node.",
		"class_note_not_reality": "None of the proven nodes use Reality, and the disguise this " +
			"class is about exists only there.",
		"class_note_not_listed": "There are Reality nodes, but their SNIs do not appear on the " +
			"censor's whitelist — masking as a site that is blocked anyway buys nothing.",
		"class_note_unproven": "The SNIs were on the list, but the disguise could not be " +
			"proven: the site does not answer, or serves a certificate for another name.",

		"howto":         "How to connect",
		"howto_1":       "Copy the link of any subscription above.",
		"howto_2":       "Paste it into your client as a subscription, not as a single server.",
		"howto_3":       "Refresh the subscription in the client. The list is rebuilt every four hours.",
		"howto_4":       "If a node stops answering, refresh the subscription again rather than debugging it: the nodes are not ours and disappear without notice.",
		"howto_clients": "Any client that understands subscriptions will do",
		"howto_note":    "The project is not affiliated with these clients and does not support them.",

		"mix":          "Catalogue mix",
		"protocols":    "Protocols",
		"inventory":    "Proven nodes",
		"filter":       "Filter by protocol",
		"filter_all":   "All",
		"search":       "Search nodes",
		"shown":        "Showing",
		"no_match":     "No node matched the filter.",
		"col_protocol": "Protocol",
		"col_country":  "Country",
		"col_trans":    "Transport",
		"col_id":       "ID",
		"col_latency":  "Latency, ms",
		"col_streak":   "Streak",
		"col_verified": "Verified",
		"masked":       "masking verified",
		"mbps_note":    "The second line in the latency column is Mbps, where throughput was measured.",

		"countries":         "Countries",
		"ago_hours":         "h ago",
		"freshness_live":    "data is fresh",
		"freshness_aging":   "data is ageing",
		"freshness_stale":   "data is stale — the pipeline may have stopped",
		"freshness_unknown": "update time unknown",
		"engine":            "Engine",
		"run_took":          "Run took",
		"seconds":           "s",
		"budget_warning":    "The run did not finish checking every candidate: the yield below is a floor, not a measurement.",
		"empty":             "Nothing to show yet: no run has completed.",
		"language":          "Language",
		"theme":             "Theme",

		// --- the node card -------------------------------------------------------------
		"detail_open":   "Details",
		"detail_title":  "Node",
		"detail_close":  "Close",
		"detail_copy":   "Copy link",
		"detail_reveal": "Show",
		"detail_hide":   "Hide",
		"detail_secret_note": "The credential and the server address are hidden. They are in the " +
			"subscription, which anyone can already open — here they are out of sight so they do " +
			"not travel in somebody's screenshot along with the window.",
		"detail_absent": "No data",

		"detail_sec_conn":  "Connection",
		"detail_sec_net":   "Network and location",
		"detail_sec_proof": "What was verified",
		"detail_sec_class": "Class and disguise",

		"detail_uri":             "Link",
		"detail_server":          "Server",
		"detail_port":            "Port",
		"detail_port_range":      "Port range",
		"detail_security":        "Security",
		"detail_sni":             "SNI",
		"detail_host":            "Host header",
		"detail_path":            "Path",
		"detail_pbk":             "Reality public key",
		"detail_sid":             "Short ID",
		"detail_fp":              "TLS fingerprint",
		"detail_alpn":            "ALPN",
		"detail_flow":            "Flow",
		"detail_packet_encoding": "UDP packet encoding",
		"detail_aid":             "AlterID",
		"detail_obfs":            "Obfuscation",
		"detail_method":          "Cipher",
		"detail_plugin":          "Plugin",
		"detail_credential":      "Credential",

		"detail_addr":   "IP address",
		"detail_ptr":    "Reverse DNS",
		"detail_asn":    "Autonomous system",
		"detail_asname": "AS name",
		"detail_isp":    "ISP",
		"detail_org":    "Network owner",
		"detail_place":  "Location",
		"detail_tz":     "Time zone",

		"detail_latency":    "Latency",
		"detail_mbps":       "Throughput",
		"detail_bytes":      "Transferred",
		"detail_streak":     "Consecutive runs passed",
		"detail_proofs":     "Proofs on record",
		"detail_failures":   "Failures on record",
		"detail_first_seen": "First seen",
		"detail_stages":     "Verification stages",

		"detail_class":         "Class",
		"detail_class_reason":  "Why this class",
		"detail_cover_subject": "Certificate issued to",
		"detail_cover_issuer":  "Issued by",
		"detail_cover_valid":   "Valid",
		"detail_cover_tls":     "TLS version",
		"detail_source":        "Source feed",

		"legal": "Legal notice",
		"legal_lede": "Read this before using anything here. What this project does, what it " +
			"does not do, and what stays on your side.",
		"legal_role": "Not a service, not a carrier, not a VPN",
		"legal_role_body": "The project operates no servers, routes and proxies no traffic, " +
			"provides no communications service and takes no money. It is a static page and " +
			"text files of links. The connection is made by your client directly to a node " +
			"somebody else runs; the project is not part of it.",
		"legal_source": "The data comes from public sources",
		"legal_source_body": "Every configuration was already published by third parties in " +
			"openly available places. The project does not create, buy, sell or commission " +
			"them. It checks whether what is already published works, and shows the result.",
		"legal_relation": "No relationship with the node operators",
		"legal_relation_body": "The owners and operators of these nodes are unknown to the " +
			"project, unaffiliated with it and unaware of it. The project does not control " +
			"their nodes, is not answerable for what they do, and can require nothing of them.",
		"legal_no_data": "No accounts, no payments, no personal data",
		"legal_no_data_body": "There is no sign-up, no payment, no cookie, no analytics and no " +
			"tracker. The site collects and stores no personal data, keeps no visit logs, and " +
			"has no traffic logs to keep — no traffic passes through it.",
		"legal_no_warranty": "No warranty",
		"legal_no_warranty_body": "Everything is provided as is, with no warranty of any kind: " +
			"not of function, availability, security, privacy or fitness for any purpose. " +
			"Proven means a node carried one HTTPS request at the moment it was measured, and " +
			"nothing more. The risk of use is the user's.",
		"legal_user": "The user's responsibility",
		"legal_user_body": "Complying with the law where you are is your responsibility. The " +
			"project does not encourage breaking it, is not intended for unlawful use and is " +
			"not offered for it. If using configurations like these is prohibited where you " +
			"are, do not use them.",
		"legal_operator": "The node operator sees your traffic",
		"legal_operator_body": "An intermediate node is somebody else's server. It sees the " +
			"addresses you reach for and can see the content of anything not protected " +
			"end to end. Do not send passwords, payment details or other sensitive data " +
			"through such nodes, and do not mistake this for anonymity.",
		"legal_takedown": "Takedown requests and complaints",
		"legal_takedown_body": "If you hold rights in something here, or operate one of these " +
			"nodes, and want an entry removed, open an issue on the repository. Well-founded " +
			"requests are acted on: the entry leaves the published lists at the next run.",
		"legal_marks": "Trademarks and names",
		"legal_marks_body": "The names of protocols, clients, sites and companies belong to " +
			"their owners and are used only to identify what is meant. The project is not " +
			"affiliated with them, not endorsed by them and does not represent them.",
		"legal_not_advice": "This text is not legal advice and cannot be. It describes how the " +
			"project is built, not your rights and obligations in your country. It cannot " +
			"remove legal risk: for your own situation, ask a lawyer in your jurisdiction.",
	},
}
