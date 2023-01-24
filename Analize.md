Анализатор ошибок
Анализ проблемных мест кода был проведен с использованием утилиты codewarrior (ссылка на репозиторий https://github.com/CoolerVoid/codewarrior.git).
Данный анализатор имеет веб-интерфейс и позволяет проверть код, написанный на нескольких языках.

Исследуемый объект
Исследуемый репозиторий https://github.com/ABenThabet/Raspi-Security представляет из себя инструмент, способный искать в сети Интернет общедоступные устройства,
которые являются устройствами Интернет-вещей.
Данное ПО по данным GitHub написано на нескольких языках: HTML, CSS, JavaScript, PHP, Python. Следовательно поиск ошибок будет проводиться по этим языкам.

Ошибки

1) 
Title: Possible Command injection
Description: Command injection is an attack in which the goal is execution of arbitrary commands on the host operating system via a vulnerable application.
Line: 2 -  $get_ip= trim(shell_exec('hostname -I'));
Path: /home/grk/Raspi-Security/www directory/dynamic_table.php
Внедрение команд — это кибератака , которая включает выполнение произвольных команд в операционной системе хоста (ОС). Как правило, субъект угрозы внедряет команды, используя уязвимость приложения, например недостаточную проверку ввода.

2)
Title: Detect insecure communication
Description: Communication without TLS
Path: /home/grk/Raspi-Security/www directory/js/google-map/data/ajax.php
Line: 11 -  		echo '{"title":"Group C","type":"directions","points":[{"lat":45.9,"lon":10.9,"title":"Title A1","html":"A1","icon":"http://maps.google.com/mapfiles/markerA.png"},{"lat":44.8,"lon":1.7,"title":"Title B1","html":","icon":"http://maps.google.com/mapfiles/markerB.png","show_infowindow":false},{"lat":51.5,"lon":-1.1,"title":"Title C1","html": C1Lorem Ipsum..","zoom":8,"icon":"http://maps.google.com/mapfiles/markerC.png"}]}'; 
Line: 18 -  		echo '{"title":"Group A","type":"marker","points":[{"lat":45.9,"lon":10.9,"title":"Title A1","html":" A1","icon":"http://maps.google.com/mapfiles/markerA.png"},{"lat":44.8,"lon":1.7,"title":"Title B1","html":"B1","icon":"http://maps.google.com/mapfiles/markerB.png","show_infowindow":false},{"lat":51.5,"lon":-1.1,"title":"Title C1","html":"Lorem Ipsum.","zoom":8,"icon":"http://maps.google.com/mapfiles/markerC.png"}]}'; 
Эту уязвимость легко использовать, и ее использование может привести к серьезным последствиям. Теоретически, если небезопасная связь является слабостью вашего приложения, злоумышленник может прослушать или перехватить ваши данные, передаваемые по сети. 

3)
Title: File Manipulation
Description: File Manipulation. this is notification
Path: /home/grk/Raspi-Security/www directory/js/file-uploader/server/php/UploadHandler.php
Line: 47 -              'mkdir_mode' => 0755,
Line: 511 -                  mkdir($version_dir, $this->options['mkdir_mode'], true);
Line: 1035 -                  mkdir($upload_dir, $this->options['mkdir_mode'], true);
Line: 1045 -                          fopen($uploaded_file, 'r'),
Line: 1055 -                      fopen('php://input', 'r'),
Line: 1068 -                      unlink($file_path);
Line: 1081 -              $handle = fopen($file_path, 'rb');
Line: 1087 -              fclose($handle);
Line: 1318 -              $success = is_file($file_path) && $file_name[0] !== '.' && unlink($file_path);
Line: 1324 -                              unlink($file);
Программное обеспечение проверяет состояние ресурса перед использованием этого ресурса, но состояние ресурса может измениться между проверкой и
использованием таким образом, что результаты проверки становятся недействительными. 
Это может привести к тому, что программное обеспечение будет выполнять недопустимые действия, когда ресурс находится в непредвиденном состоянии.
Эта уязвимость может иметь отношение к безопасности, когда злоумышленник может влиять на состояние ресурса между проверкой и использованием.

4)
Title: Possible XSS
Description: notification at possible XSS
Path: /home/grk/Raspi-Security/www directory/js/file-uploader/server/php/UploadHandler.php
Line: 1239 -          if ($print_response && isset($_GET['download'])) {
тип атаки на веб-системы, заключающийся во внедрении в выдаваемую веб-системой страницу вредоносного кода (который будет выполнен на компьютере пользователя при открытии им этой страницы) и взаимодействии этого кода с веб-сервером злоумышленника. Является разновидностью атаки «Внедрение кода».
Специфика подобных атак заключается в том, что вредоносный код может использовать авторизацию пользователя в веб-системе для получения к ней расширенного доступа или для получения авторизационных данных пользователя. Вредоносный код может быть вставлен в страницу как через уязвимость в веб-сервере, так и через уязвимость на компьютере пользователя.

5)
Title: Header injection
Description: HTTP_HOST is remotely set via Host Header and poor usage often leads to injection or redirection attacks.
Path: /home/grk/Raspi-Security/www directory/js/file-uploader/server/php/UploadHandler.php
Line: 186 -              (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : ($_SERVER['SERVER_NAME'].
Line: 1097 -      protected function header($str) {
Line: 1098 -          header($str);
Line: 1111 -                  $this->header('Location: '.sprintf($redirect, rawurlencode($json)));
Line: 1197 -              $this->header('Content-Disposition: attachment; filename="'.$file_name.'"');
Line: 1199 -              $this->header('Content-Type: '.$this->get_file_type($file_path));
Line: 1200 -              $this->header('Content-Disposition: inline; filename="'.$file_name.'"');
Line: 1202 -          $this->header('Content-Length: '.$this->get_file_size($file_path));
Line: 1203 -          $this->header('Last-Modified: '.gmdate('D, d M Y H:i:s T', filemtime($file_path)));
Line: 1217 -          $this->header('Access-Control-Allow-Origin: '.$this->options['access_control_allow_origin']);
это общий класс уязвимостей безопасности веб-приложений, который возникает, когда заголовки протокола передачи гипертекста (HTTP) динамически генерируются на основе пользовательского ввода. Внедрение заголовка в ответы HTTP может позволить разделить ответ HTTP , зафиксировать сеанс с помощью заголовка Set-Cookie, межсайтовый скриптинг (XSS) и вредоносные атаки с перенаправлением через заголовок местоположения. Внедрение заголовков HTTP является относительно новой областью для веб-атак, и в первую очередь она была впервые применена Амитом Кляйном в его работе о контрабанде/разделении запросов/ответов. 

6)
Title: SHow inputs like get/post/cookies etc...
Description: notification
Path: /home/grk/Raspi-Security/www directory/modify.php
Line: 9 -  $id=$_POST["ID"];


Все вышеперечисленые уязвимые места встречаются неоднократно, в коде есть множество примеров указанных ошибок. 
Но большинство из них анализатр отмечает низким уровнем угрозы.

