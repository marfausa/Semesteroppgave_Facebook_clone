



/**
 * Wrapper around fetch() for JSON data
 * 
 * @param {*} path The path (or URL)
 * @param {*} method Request method, defaults to GET
 * @param {*} headers Additional headers
 * @returns The response data, as an object, or null if the request failed
 */
async function fetch_json(path, method='GET', headers = {}) {
    const resp = await fetch(path, {
        method, 
        headers:{
            accept: 'application/json',
            ...headers
        }});
    if(resp.ok) {
        return await resp.json();
    } else {
        console.error('Request failed:', resp.status, resp.statusText);
        return null;
    }
}

/**
 * Get list of users from server
 * 
 * @returns A list of simple user objects (only id and username)
 */
async function list_users() {
    return await fetch_json('/users') || [];
}

/**
 * Get a user profile from the server
 * @param {*} userid The numeric user id
 * @returns A user object
 */
async function get_profile(userid) {
    return await fetch_json(`/users/${userid}`);
}

/**
 * Format a key-value field
 * 
 * @param {*} key The key
 * @param {*} value The value
 * @param {*} options Object with options {optional: bool, className: string, long: bool}
 * @returns HTML text
 */
function format_field(key, value, options = {}) {
    if(options.optional && !value)
        return '';
    let classNames = 'field';
    if(options.className) // if we need extra styling
        classNames = `${classNames} ${options.className}`;
    if(options.long) // if the value is a longer text
        classNames = `${classNames} long`;
    const val = options.long ? `<div class="value">${value || ''}</div>` : ` <span class="value">${value || ''}</span>`
    return `<li class="${classNames}"><span class="key">${key}</span>${val}</li>`
}

/**
 * Display a user as a HTML element
 * 
 * @param {*} user A user object
 * @param {*} elt An optional element to render the user into
 * @returns elt or a new element
 */
function format_profile(user, elt) {
    if(!elt) 
        elt = document.createElement('div');
    elt.classList.add('user'); // set CSS class
    if(user.id == current_user_id) { // current_user_id is a global variable (set on 'window')
        elt.classList.add('me');
    }
    // TODO: is this unsafe?
    elt.innerHTML = `
    <img src="${user.picture_url || '/unknown.png'}" alt="${user.username}'s profile picture">
    <div class="data">
        ${format_field('Name', user.username)}
        <div class="more">
            ${format_field('Birth date', user.birthdate)}
            ${format_field('Favourite colour', user.color)}
            ${format_field('About', user.about, 'long')}
        </div>
    </div>
    <div class="controls">
        ${window.current_user_id == user.id ? '' : `<button type="button" data-user-id="${user.id}" data-action="add_buddy">Add buddy</button>`}
    </div>
    `;
    return elt;
}

/**
 * Perform an action, such as a button click.
 * 
 * Get the action to perform and any arguments from the 'data-*' attributes on the button element.
 * 
 * @param {*} element A button element with `data-action="…"` set
 * @returns true if action was performed
 */
async function do_action(element) {
    if(element.dataset.action === 'add_buddy') {
        result = await fetch_json(`/buddies/${element.dataset.userId}`, 'POST')
        console.log(result);
        return true;
    }
    return false;
}
