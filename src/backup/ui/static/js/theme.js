var theme;

$(document).ready(function() {
    theme = localStorage.getItem('notary-theme');
    if (theme) {
        if (theme == 'light') {
            $('.dark').addClass('light').removeClass('dark');
        }
    } else {
        theme = 'light'
        localStorage.setItem('notary-theme', theme);
    }
})

function toggleTheme() {
    if (theme == 'light') {
        theme = 'dark'
        $('.light').addClass('dark').removeClass('light');
        if (typeof editor === 'undefined' || editor === null) {
            console.log("Editor not found!")
        } else {
            console.log("Editor found!")
            monaco.editor.setTheme('notaryDarkTheme');
        }
    } else {
        theme = 'light'
        $('.dark').addClass('light').removeClass('dark');
        if (typeof editor === 'undefined' || editor === null) {
            console.log("Editor not found!")
        } else {
            console.log("Editor found!")
            monaco.editor.setTheme('notaryLightTheme');
        }
    }
    localStorage.setItem('notary-theme', theme);
}
