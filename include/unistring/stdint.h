/* Override libunistring's stdint compat header to use the system one rather
 * than its own which pollutes everything with MACROS redefining the types.
 *
 * This will be fixed in a future libunistring release, see:
 * https://savannah.gnu.org/bugs/index.php?67590
*/

#include <stddef.h>
#include <stdint.h>

