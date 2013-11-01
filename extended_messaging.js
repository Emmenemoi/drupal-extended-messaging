$(document).ready(function() {
	
	/** THIS technique is bad because of CORS.... tsssssssssssssss
	if ($("#extended_messaging_original", top.document).length == 0) {
		$('body').html("");
		$('html,body').width('100%').height('100%');
		$('body').append($('<iframe>').attr({src: window.location.href, width:'100%', height: '100%', border:0, id:"extended_messaging_original"}));
		//$.getScript(Drupal.settings.extended_messaging.script);
		
		var fileref=document.createElement('script');
		fileref.setAttribute("type","text/javascript");
		fileref.setAttribute("src", Drupal.settings.extended_messaging.script);
		document.getElementsByTagName("head")[0].appendChild(fileref);
	}*/
	
	
	// Manage all links through an ajaxwrapper
	/*var fileref=document.createElement('script');
	fileref.setAttribute("type","text/javascript");
	fileref.setAttribute("src", Drupal.settings.extended_messaging.script);
	document.getElementsByTagName("head")[0].appendChild(fileref);

	$('body').append($('<iframe>').attr({width:'100%', height: '100%', border:0, id:"extended_messaging_original"}).html($('body').html()));

	$('a').live('click',function(event){
		event.preventDefault();
		$('#extended_messaging_original').load(this.href);
		/*
		$.get(this.href,{},function(response){
			$('#extended_messaging_original').html(response);
		});
	});
	*/
});