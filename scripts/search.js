function toProperCase(word) {
    startLetter = word.charAt(0).toUpperCase();
    return startLetter + word.slice(1).toLowerCase();
}

function displayResults (results, store) {
    const searchResults = document.getElementById('results');
    if (results.length) {
        let resultList = '';
        // Iterate and build result list elements
        for (const n in results) {

            const item = store[results[n].ref];

            const url = item.url.startsWith('/') ? `http:${item.url}` : item.url;
            const topDirectory = new URL(url).pathname.split('/')[1];

            let resultItem;
            switch (topDirectory) {
                case 'categories':
                    resultItem = `
                        <a href="${item.url}">
                        <h3 class="search-result-title">${item.title}</h3>
                        <span class="search-result-category">(Category)</span>
                        <p class="search-result-content">Listing of all pages within the ${item.title} category</p>
                        </a>
                    `;
                    break;
                case 'tags':
                    resultItem = `
                        <a href="${item.url}">
                        <h3 class="search-result-title">${item.title}</h3>
                        <span class="search-result-category">(Tag Listing)</span>
                        <p class="search-result-content">Listing of all pages tagged with ${item.title}</p>
                        </a>
                    `;
                    break;
                case 'walkthrough':
                    resultItem = `
                        <a href="${item.url}">
                        <h3 class="search-result-title">${item.title}</h3>
                        <span class="search-result-category">(Walkthrough)</span>
                        <p class="search-result-content result-quote">${item.content.substring(0, 150)}...</p>
                        </a>
                    `;
                    break;
                case 'ctf':
                    resultItem = `
                        <a href="${item.url}">
                        <h3 class="search-result-title">${item.title}</h3>
                        <span class="search-result-category">(CTF Guide)</span>
                        <p class="search-result-content result-quote">${item.content.substring(0, 150)}...</p>
                        </a>
                    `;
                    break;
                default:
                    resultItem = `
                        <a href="${item.url}">
                        <h3 class="search-result-title">${item.title}</h3>
                        <span class="search-result-category">(${toProperCase(topDirectory)})</span>
                        <p class="search-result-content result-quote">${item.content.substring(0, 150)}...</p>
                        </a>
                    `;
            }
            resultList += resultItem;
        }
        searchResults.innerHTML = resultList;
    } else {
        searchResults.innerHTML = '<div>No results found.</div>';
    }
}

// Get the query parameter(s)
const params = new URLSearchParams(window.location.search)
const query = params.get('query')

// Perform a search if there is a query
if (query) {
    // Retain the search input in the form when displaying results
    document.getElementById('search-input').setAttribute('value', query)

    const idx = lunr(function () {
        this.ref('id')
        this.field('title', {
            boost: 15
        });
        this.field('tags', {
            boost: 12
        });
        this.field('categories', {
            boost: 10
        });
        this.field('content', {
            boost: 5
        });

        for (const key in window.store) {
            this.add({
                id: key,
                title: window.store[key].title,
                tags: window.store[key].tags,
                categories: window.store[key].categories,
                content: window.store[key].content
            });
        }
    })

    // Perform the search
    const results = idx.search(query)
    // Update the list with results
    displayResults(results, window.store)
}
