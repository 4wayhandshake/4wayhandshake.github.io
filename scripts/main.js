// // When the user scrolls the page, execute myFunction
// window.onscroll = function() {myFunction()};
//
// // Add the sticky-active class to any sticky element
// // when you reach its scroll position.
// // Remove "sticky" when you leave the scroll position
// // Elements with this behaviour should start with position:static and sticky-active
// function myFunction() {
//     const stickyElements = document.querySelector(".sticky");
//     for (ele in stickyElements) {
//         const offset = ele.offsetTop;
//         if (window.pageYOffset >= offset) {
//             ele.classList.add("sticky-active")
//         } else {
//             ele.classList.remove("sticky-active");
//         }
//     }
// }

function clearAllActiveNavItems() {
    liElements = document.querySelectorAll('#TableOfContents li');
    liElements.forEach((ele) => {
        ele.classList.remove('active');
    });
}

window.addEventListener('DOMContentLoaded', () => {

    // Hugo's Table of Contents only tracks the largest three heading types
    const headingTypes = ['h1','h2','h3'];

    const scrollableElement = document.querySelector('#toc');
    if (!scrollableElement) return;

	const observer = new IntersectionObserver(elements => {
        elements.filter( ele => {
            return headingTypes.includes(ele.target.tagName.toLowerCase())
        }).forEach(ele => {
            const id = ele.target.getAttribute('id');
    		if (ele.intersectionRatio > 0) {
                // Setting 'active' class on found element
                clearAllActiveNavItems();
    			const anchorEle = document.querySelector(`nav li a[href="#${id}"]`)
                if (anchorEle) {
                    anchorEle.parentElement.classList.add('active');
                    scrollableElement.scrollTo({
                        top: anchorEle.offsetTop,
                        left: 0,
                        // behavior: "smooth",
                    });
                }
    		}
        });
	});

	// Track all headings that have an `id` applied
    headingTypes.forEach((headingType) => {
        document.querySelectorAll(`${headingType}[id]`).forEach((headingElement) => {
            observer.observe(headingElement);
        });
    });

    const navAnchors = document.querySelectorAll('#TableOfContents li a');
    navAnchors.forEach( anchorEle => {
        anchorEle.addEventListener("click", (event) => {
            // Prevent the default scroll action
            event.preventDefault();
            // Find the element that this anchor links to
            const tgt = document.querySelector(anchorEle.getAttribute('href'));
            if (tgt) {
                // Override normal scrolling,using (x,y) coords.
                // Try to detect chrome browsers and circumvent smooth scrolling for them.
                let behavior;
                if (navigator.userAgent.toLowerCase().includes("chrome")) {
                    behavior = "instant";
                } else {
                    behavior = "smooth";
                }
                window.scrollTo({
                    top: tgt.offsetTop - 100,
                    left: 0,
                    behavior: behavior,
                });
            }
        });
    });

});
