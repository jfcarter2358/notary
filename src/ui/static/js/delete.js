function refreshUsers() {
    hostname = window.location.hostname
    port = window.location.port
    $.ajax({
        type: 'Get',
        url: '/api/user',
        success: function(response) {
            $("#user-card").empty();
            $("#user-card").removeClass('loading');
            $("#user-card").append('<ul class="w3-ul" id="user-list"></ul>')
            for (var i in response.users) {
                $("#user-list").append('<li class="w3-display-container">' + 
                    response.users[i]['username'] + 
                    '<button class="w3-button w3-display-right" id="' + response.users[i]['id'] + '" onclick="showModal(this)"><i class="fas fa-trash-alt"></i></button>' + 
                    '</li>');
            }
        },
        error: function(response) {
            console.log(response)
        }
    });
}

$(document).ready(
    refreshUsers()
)

function deleteUser(currentElement) {
    userID = $(currentElement).prop('id')
    document.getElementById('modal').style.display='none'
    $.ajax({
        type: "DELETE",
        url: '/api/user/' + userID,
        success: function(response) {
            alert("User successfully deleted")
            refreshUsers()
        },
        error: function(response) {
            alert("There was an issue deleting the user")
        }
    });
    
}

function showModal(currentElement) {
    document.getElementById('modal').style.display = 'block'
    $("#model_delete").attr("id",$(currentElement).prop('id'));
}