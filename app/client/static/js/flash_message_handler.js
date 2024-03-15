// Function to automatically hide flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    var flashes = document.querySelectorAll('.flashes li');

    if (flashes.length > 0) {
        setTimeout(function() {
            flashes.forEach(function(flash) {
                flash.style.animation = 'fadeOutDown 1s forwards ease-out';
            });

            setTimeout(function() {
                flashes.forEach(function(flash) {
                    flash.style.display = 'none';
                });
            }, 1000); // Adjust this timeout based on your fadeOutDown animation duration
        }, 5000); // Adjust this timeout based on your desired delay before hiding
    }
});
