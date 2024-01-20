function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const button = document.querySelector('.sidebar-btn');

    sidebar.classList.toggle('open');

    button.style.left = buttonLeftPosition;
}

function showSection(sectionId) {
    const sections = document.querySelectorAll('.section');
    const links = document.querySelectorAll('.sidebar li');

    sections.forEach(section => section.classList.remove('active'));
    document.getElementById(sectionId).classList.add('active');

    links.forEach(link => link.classList.remove('active'));
    document.getElementById(sectionId + '-link').classList.add('active');

    localStorage.setItem('activeSection', sectionId);
}

function initializeActiveSection() {
    const previouslyActiveSection = localStorage.getItem('activeSection');
    if (previouslyActiveSection) {
        showSection(previouslyActiveSection);
    }
}

document.querySelector('.sidebar ul').addEventListener('click', function(event) {
    if (event.target.tagName === 'LI') {
        const sectionId = event.target.id.replace('-link', '');
        showSection(sectionId);
    }
});

document.addEventListener('DOMContentLoaded', initializeActiveSection);

const debouncedResize = debounce(function () {
    // Your resize logic here (if any)
}, 250);
window.addEventListener('resize', debouncedResize);

const throttledScroll = throttle(function () {
    // Your scroll logic here (if any)
}, 250);
window.addEventListener('scroll', throttledScroll);

function debounce(func, wait) {
    let timeout;
    return function () {
        const context = this;
        const args = arguments;
        clearTimeout(timeout);
        timeout = setTimeout(function () {
            func.apply(context, args);
        }, wait);
    };
}

function throttle(callback, limit) {
    let wait = false;
    return function () {
        if (!wait) {
            callback.call();
            wait = true;
            setTimeout(function () {
                wait = false;
            }, limit);
        }
    };
}
