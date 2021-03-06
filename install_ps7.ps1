$SOFT_ENV = "$(Split-Path -Path $(Split-Path -Path $MyInvocation.MyCommand.Path))\soft_environment"

if(!(Test-Path "C:\Program Files\PowerShell\7\pwsh.exe")){
	# Install PS7
	$Name = "msiexec"
	& msiexec.exe /package $SOFT_ENV\sys\pwsh\PowerShell-7.2.1-win-x64.msi /quiet # /forcerestart
	Write-Host -noNewLine "Install PowerShell-7:  "
	while(Get-Process |where {$_.ProcessName -eq $Name} ){
		foreach($ix in "|","/","-","\"){
			Write-Host -ForegroundColor Green -noNewLine "`b$ix"
			Start-Sleep -Milliseconds 250
		}
	}
	Write-Host -noNewLine "`b[ "; Write-Host -ForegroundColor Green -noNewLine "OK"; Write-Host " ]"
}

<#
Установщик Windows®. Версия 5.0.7601.24535 

msiexec /Option <обязательный параметр> [необязательный параметр]

Параметры установки
	</package | /i> <Product.msi>
		Установка или настройка продукта
	/a <Product.msi>
		Административная установка - установка продукта в сеть
	/j<u|m> <Product.msi> [/t <список преобразований>] [/g <код языка>]
		Объявление о продукте: "m" - всем пользователям; "u" - текущему пользователю
	</uninstall | /x> <Product.msi | Код_продукта>
		Удаление продукта
Параметры отображения
	/quiet
		Тихий режим, без взаимодействия с пользователем
	/passive
		Автоматический режим - только указатель хода выполнения
	/q[n|b|r|f]
		Выбор уровня интерфейса пользователя
		n - Без интерфейса
		b - Основной интерфейс
		r - Сокращенный интерфейс
		f - Полный интерфейс (по умолчанию)
	/help
		Вывод справки по использованию
Параметры перезапуска
	/norestart
		Не перезапускать после завершения установки
	/promptrestart
		Запрашивать перезапуск при необходимости
	/forcerestart
		Всегда перезапускать компьютер после завершения установки
Параметры ведения журнала
	/l[i|w|e|a|r|u|c|m|o|p|v|x|+|!|*] <файл_журнала>
		i - сообщения о состоянии
		w - сообщения об устранимых ошибках
		e - все сообщения об ошибках
		a - запуски действий
		r - записи, специфические для действий
		u - запросы пользователя
		c - начальные параметры интерфейса пользователя
		m - сведения о выходе из-за недостатка памяти или неустранимой ошибки
		o - сообщения о недостатке места на диске
		p - свойства терминала
		v - подробный вывод
		x - дополнительные отладочные сведения
		+ - добавление в существующий файл журнала
		! - сбрасывание каждой строки в журнал
		* - заносить в журнал все сведения, кроме параметров "v" и "x"
	/log <файл_журнала>
		Равнозначен /l* <файл_журнала>
Параметры обновления
	/update <Update1.msp>[;Update2.msp]
		Применение обновлений
	/uninstall <Код_Guid_обновления>[;Update2.msp] /package <Product.msi | код_продукта>
		Удаление обновлений продукта
Параметры восстановления
	/f[p|e|c|m|s|o|d|a|u|v] <Product.msi | код_продукта>
		Восстановление продукта
		p - только при отсутствии файла
		o - если файл отсутствует или установлена старая версия (по умолчанию)
		e - если файл отсутствует или установлена такая же либо старая версия
		d - если файл отсутствует или установлена другая версия
		c - если файл отсутствует или контрольная сумма не совпадает с подсчитанным значением
		a - принудительная переустановка всех файлов
		u - все необходимые элементы реестра, специфические для пользователя (по умолчанию)
		m - все необходимые элементы реестра, специфические для компьютера (по умолчанию)
		s - все существующие ярлыки (по умолчанию)
		v - запуск из источника с повторным кэшированием локальных пакетов
Настройка общих свойств
	[PROPERTY=PropertyValue]

Обратитесь к руководству разработчиков установщика Windows® за дополнительными
сведениями по использованию командной строки.

© Корпорация Майкрософт. Все права защищены.
В некоторых частях программы использованы разработки Independent JPEG Group.
#>