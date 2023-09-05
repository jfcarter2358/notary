$(document).ready(
    function() {
        user_id = window.location.pathname.split('/')[3]
        $("#edit_form").addClass('loading');
        $.ajax({
            type: 'GET',
            url: '/api/user/' + user_id,
            success: function(response) {
                $("#username").val(response.user['username'])
                $("#family_name").val(response.user['family_name'])
                $("#given_name").val(response.user['given_name'])
                $("#email").val(response.user['email'])
                $("#password").val(response.user['password'])
                $("#groups").val(response.user['groups'])
                $("#roles").val(response.user['roles'])
                $("id").val(response.user['id'])
                $("#edit_form").attr('action', '/api/user/' + response.user['id'])
                $("#edit_form").removeClass('loading');
            },
            error: function(response) {
                console.log(response)
            }
        });
    }
)