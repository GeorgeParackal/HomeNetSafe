function alertMessage(status, message) {
    var alertMessage = document.createElement("div")
    if (status == 'success') {
      alertMessage.setAttribute("class", "alert-success")
    }
    else if (status == 'warn') {
        alertMessage.setAttribute("class", "alert-warn")
    }
    else {
      alertMessage.setAttribute("class", "alert-error")
    }
  
    alertMessage.textContent = message
  
    var bodyContainer = document.getElementsByClassName("container")[0]
    bodyContainer.appendChild(alertMessage)
  
    setTimeout(
      function() {
        alertMessage.remove()
      }, 3000
    )
  }