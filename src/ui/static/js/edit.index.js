$(document).ready(
    function() {
        $.ajax({
            type: 'GET',
            url: '/api/user',
            success: function(response) {
                $("#user-card").empty();
                $("#user-card").removeClass('loading');
                $("#user-card").append('<ul class="w3-ul" id="user-list"></ul>')
                for (var i in response.users) {
                    console.log(response.users[i])
                    $("#user-list").append('<li class="w3-display-container">' + 
                        response.users[i]['username'] + 
                        '<a href="/ui/edit/' + response.users[i].id + '" class="w3-button w3-display-right"><i class="fas fa-edit"></i></a>' + 
                        '</li>');
                }
            },
            error: function(response) {
                console.log(response)
            }
    });
    }
)