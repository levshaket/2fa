function get_acode_ttl(elem) {
	var account = elem.name;
	var acode_element = document.getElementById(account+"_acode");
	var ttl_element = document.getElementById(account+"_ttl");
	var abort = false;
	elem.addEventListener("mouseout", function(){
		if (xhttp){
			xhttp.abort();
		};
		acode_element.innerHTML = "";
		ttl_element.innerHTML= "";
		abort = true;
	});
	if (!abort) {
		var xhttp = new XMLHttpRequest(); //old IE5/IE6 browsers using ActiveX object not supported
		xhttp.onreadystatechange = function() {	
			if (xhttp.readyState === 0) {
				acode_element.innerHTML = "initializing request..";
			} else if (xhttp.readyState === 1) {
				acode_element.innerHTML = "server connection established..";
			} else if (xhttp.readyState === 2) {
				acode_element.innerHTML = "request received..";
			} else if (xhttp.readyState === 3) {
				acode_element.innerHTML = "processing request..";
			} else if (xhttp.readyState === 4 && xhttp.status === 200) {
				var response = xhttp.response;
				acode_element.innerHTML = response.acode;
				ttl_element.innerHTML = response.ttl;
			} else {
				acode_element.innerHTML = "server response could not be processed"
			};
		xhttp.open("POST", "/user", true);
		xhttp.setRequestHeader("Content-Type", "multipart/form-data");
		xhttp.responseType = "json";
		var form_data = new FormData();
		form_data.append("csrf_token","{{csrf_token}}");
		form_data.append("account", account);
		xhttp.send(form_data);
	} else {
		return "server request aborted";
	};	
};
