var fileName;
function createCMSSignatureFromBase64Call() {
	var file = $('#fileId').get(0).files[0];
	fileName = file.name;
	var formData = new FormData();
	formData.append("file", file);
	// Отправляем файл на сервер, чтобы из него сделать base64 string 
	$.ajax({
		type: "POST",
		url: '/NcaLayer/FileForCMS',
		cache: false,
		processData: false,
		contentType: false,
		contentType: false,
		data: formData
	}).done(function (data) {
		if (data !== null && data !== "") {
			var flag = true;
			//console.log("data:  ", data);
			// Подписываем base64 string
			createCMSSignatureFromBase64("PKCS12", "SIGNATURE", data, flag, "createCMSSignatureFromBase64Back");
		} else {
			alert("Нет данных для подписи!");
		}
	});
}

function createCMSSignatureFromBase64Back(result) {
	if (result['code'] === "500") {
		alert(result['message']);
	}
	else
		if (result['code'] === "200") {
			var res = result['responseObject'];
			console.log("res: ", res);
			// Преобразовываем из base64 string to bytes array
			const data = atob(res);
			const array = Uint8Array.from(data, b => b.charCodeAt(0));
			// Отправляем файл клиенту
			var blob = new Blob([array], { type: "application/octet-stream" });
			var link = document.createElement('a');
			link.href = window.URL.createObjectURL(blob);
			link.download = fileName + '.cms';
			link.click();
		}
}

