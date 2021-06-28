"use strict";(function(a){if("object"==typeof exports&&"undefined"!=typeof module)module.exports=a();else if("function"==typeof define&&define.amd)define([],a);else{var b;b="undefined"==typeof window?"undefined"==typeof global?"undefined"==typeof self?this:self:global:window,b.SessionCheck=a()}})(function(){return function(){function b(d,e,g){function a(j,i){if(!e[j]){if(!d[j]){var f="function"==typeof require&&require;if(!i&&f)return f(j,!0);if(h)return h(j,!0);var c=new Error("Cannot find module '"+j+"'");throw c.code="MODULE_NOT_FOUND",c}var k=e[j]={exports:{}};d[j][0].call(k.exports,function(b){var c=d[j][1][b];return a(c||b)},k,k.exports,b,d,e,g)}return e[j].exports}for(var h="function"==typeof require&&require,c=0;c<g.length;c++)a(g[c]);return a}return b}()({1:[function(a,b){(function(){"use strict";b.exports=function(a){var b;if(this.request_check_count=0,this.cooldownPeriod=a.cooldownPeriod||5,this.subject=a.subject,a.ssoToken)this.ssoTokenName=a.ssoTokenName||"iPlanetDirectoryPro",this.ssoToken=a.ssoToken,this.amUrl=a.amUrl+"/sessions?_action=validate",this.validationHandler=function(b){try{var c=JSON.parse(b)}catch(b){return void a.invalidSessionHandler(b.message,this.request_check_count)}return c.valid?this.subject&&this.subject!==c.uid?void a.invalidSessionHandler("subject_mismatch",this.request_check_count):void(a.initialSessionSuccessHandler&&1===this.request_check_count&&a.initialSessionSuccessHandler()):void a.invalidSessionHandler("invalid_session",this.request_check_count)}.bind(this);else{if(a.redirectUri?this.redirectUri=a.redirectUri:(b=document.createElement("a"),b.href="sessionCheck.html",this.redirectUri=b.href),this.idToken=a.idToken,this.clientId=a.clientId,this.opUrl=a.opUrl,this.responseType=a.responseType||"id_token","none"===this.responseType&&!this.idToken)throw"When using the 'none' response type, you must supply an idToken value to use as a hint when calling the OP.";"id_token"===this.responseType&&(this.scope=a.scope||"openid"),this.iframe=document.createElement("iframe"),this.iframe.setAttribute("id","sessionCheckFrame"+this.clientId),this.iframe.setAttribute("style","display:none"),document.getElementsByTagName("body")[0].appendChild(this.iframe),this.eventListenerHandle=function(b){b.origin!==document.location.origin||("sessionCheckFailed"===b.data.message&&a.invalidSessionHandler&&a.invalidSessionHandler(b.data.reason,this.request_check_count),"sessionCheckSucceeded"===b.data.message&&(a.sessionClaimsHandler&&b.data.claims&&a.sessionClaimsHandler(b.data.claims,this.request_check_count),a.initialSessionSuccessHandler&&1===this.request_check_count&&a.initialSessionSuccessHandler()))}.bind(this),window.addEventListener("message",this.eventListenerHandle),this.subject&&sessionStorage.setItem("sessionCheckSubject",this.subject),this.idToken&&sessionStorage.setItem("sessionCheckIdToken",this.idToken)}return this};var a=function(a){if(a.ssoToken){var b=new XMLHttpRequest;b.addEventListener("load",function(){a.validationHandler(this.responseText)}),b.open("POST",a.amUrl),b.setRequestHeader(a.ssoTokenName,a.ssoToken),b.setRequestHeader("Accept-API-Version","resource=2.1, protocol=1.0"),b.send()}else{if(!a.iframe)return;var c=a.opUrl+"?prompt=none&client_id="+a.clientId+"&response_type="+a.responseType+"&redirect_uri="+a.redirectUri;if("id_token"===a.responseType){var d=Math.floor(1e5*Math.random());sessionStorage.setItem("sessionCheckNonce",d),c+="&nonce="+d}a.scope&&(c+="&scope="+a.scope),a.idToken&&(c+="&id_token_hint="+a.idToken),a.iframe.contentWindow.location.replace(c)}};b.exports.prototype.triggerSessionCheck=function(){(function(){var b=new Date().getTime();(!this.checkSessionTimestamp||this.checkSessionTimestamp+1e3*this.cooldownPeriod<b)&&(this.checkSessionTimestamp=b,this.request_check_count++,a(this))}).call(this)},b.exports.prototype.destroy=function(){this.iframe&&this.iframe.parentNode&&this.iframe.parentNode.removeChild(this.iframe),this.iframe=null,removeEventListener("message",this.eventListenerHandle,!1),this.eventListenerHandle=null}})()},{}]},{},[1])(1)});
